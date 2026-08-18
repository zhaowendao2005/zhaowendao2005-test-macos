import { execSync, spawn, spawnSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import os from 'os';

function logInfo(msg) {
  console.log(`\x1b[36m▶ ${msg}\x1b[0m`);
}

function logSuccess(msg) {
  console.log(`\x1b[32m✔ ${msg}\x1b[0m`);
}

function logWarning(msg) {
  console.log(`\x1b[33m⚠️ ${msg}\x1b[0m`);
}

function logError(msg) {
  console.log(`\x1b[31m✖ ${msg}\x1b[0m`);
}

function setGhSecret(secretName, secretValue) {
  const result = spawnSync('gh', ['secret', 'set', secretName], {
    input: secretValue,
    stdio: ['pipe', 'inherit', 'inherit'],
    shell: true,
  });
  if (result.status !== 0) {
    throw new Error(`设置 GitHub Secret ${secretName} 失败`);
  }
}

function run(command, options = {}) {
  return execSync(command, { stdio: 'inherit', ...options });
}

function runQuiet(command) {
  try {
    return execSync(command, { stdio: ['pipe', 'pipe', 'pipe'] }).toString().trim();
  } catch (e) {
    return '';
  }
}

// xcodebuild 封装：自动重试。macos-15 runner 镜像存在已知 bug
// (actions/runner-images#13560)：storyboard 编译偶发报 “iOS Platform Not
// Installed” 而 SDK 实际存在，重试+清理 DerivedData 可稳定规避。
function runXcodebuild(buildArgs, maxRetries = 3) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      run(buildArgs);
      return;
    } catch (err) {
      logWarning(`xcodebuild 第 ${attempt}/${maxRetries} 次执行失败，正在清理缓存并重试...`);
      if (attempt < maxRetries) {
        runQuiet('rm -rf ~/Library/Developer/Xcode/DerivedData');
      } else {
        throw err;
      }
    }
  }
}

function importP12ToKeychain(certPath, p12Password, keychainPath, tempDir) {
  let imported = false;
  try {
    run(`security import "${certPath}" -P "${p12Password}" -A -t cert -f pkcs12 -k "${keychainPath}" -T /usr/bin/codesign -T /usr/bin/security`);
    imported = true;
  } catch (err) {
    logWarning('直接 security import 遇到兼容性问题，正在使用 OpenSSL 进行兼容格式重转换...');
  }

  if (!imported) {
    const pemPath = path.join(tempDir, 'compat_cert.pem');
    const compatP12Path = path.join(tempDir, 'compat_cert.p12');

    // 1. 使用 openssl 解码为 PEM
    try {
      run(`openssl pkcs12 -in "${certPath}" -passin pass:"${p12Password}" -nodes -out "${pemPath}" -legacy`);
    } catch (e) {
      run(`openssl pkcs12 -in "${certPath}" -passin pass:"${p12Password}" -nodes -out "${pemPath}"`);
    }

    // 2. 重新打包为 macOS Keychain 100% 兼容的 PKCS12
    try {
      run(`openssl pkcs12 -export -in "${pemPath}" -out "${compatP12Path}" -passout pass:"${p12Password}" -legacy`);
      run(`security import "${compatP12Path}" -P "${p12Password}" -A -t cert -f pkcs12 -k "${keychainPath}" -T /usr/bin/codesign -T /usr/bin/security`);
    } catch (e) {
      run(`security import "${pemPath}" -k "${keychainPath}" -A -T /usr/bin/codesign -T /usr/bin/security`);
    }
  }
}

function findFile(dir, pattern) {
  if (!fs.existsSync(dir)) return null;
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (pattern.test(entry.name)) {
      return fullPath;
    }
    if (entry.isDirectory()) {
      const sub = findFile(fullPath, pattern);
      if (sub) return sub;
    }
  }
  return null;
}

// 下载 IPA 前，把本地已存在的旧 .ipa 加上时间戳备份，以便新文件能直接写入覆盖。
function backupExistingIpa(dir) {
  if (!fs.existsSync(dir)) return;
  const entries = fs.readdirSync(dir);
  const oldFiles = entries.filter((f) => /\.ipa$/i.test(f));
  if (oldFiles.length === 0) return;
  const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  for (const f of oldFiles) {
    const src = path.join(dir, f);
    const ext = path.extname(f);
    const base = path.basename(f, ext);
    const dst = path.join(dir, `${base}-${ts}${ext}`);
    fs.renameSync(src, dst);
    logInfo(`旧版本已备份为: ${path.basename(dst)}`);
  }
}

// -------------------------------------------------------------
// 本地 Windows/Linux 客户端：自动读取证书 -> 配置 GitHub Secrets -> 触发构建 -> 下载 IPA
// -------------------------------------------------------------
async function handleLocalTrigger(rootDir) {
  console.log('\n\x1b[32m================================================\x1b[0m');
  console.log('\x1b[32m🚀 正在启动本地 iOS 云端自动化打包与证书配置助手\x1b[0m');
  console.log('\x1b[32m================================================\x1b[0m');

  // 1. 检查 gh CLI
  const ghVersion = runQuiet('gh --version');
  if (!ghVersion) {
    logError('未检测到 GitHub CLI (gh)。请先安装 gh 命令行工具 (https://cli.github.com/)');
    process.exit(1);
  }

  const authStatus = runQuiet('gh auth status');
  if (authStatus.includes('Logged in') === false && runQuiet('gh auth token') === '') {
    logError('GitHub CLI 尚未登录，请先在终端运行 `gh auth login` 登录您的 GitHub 账号。');
    process.exit(1);
  }
  logSuccess('GitHub CLI 已就绪并已登录！');

  // 2. 检查本地 ./p12 文件夹中的证书与描述文件
  const p12Dir = path.join(rootDir, 'p12');
  const p12File = findFile(p12Dir, /\.p12$/i);
  const mpFile = findFile(p12Dir, /\.mobileprovision$/i);
  const pwdFile = findFile(p12Dir, /(密码|password|\.txt$)/i);

  if (!p12File || !mpFile) {
    logError(`在目录 ${p12Dir} 下未找到 .p12 证书或 .mobileprovision 描述文件！`);
    console.log('请将您的【.p12证书文件】和【.mobileprovision描述文件】放入项目的 p12/ 文件夹中。');
    process.exit(1);
  }

  let p12Password = process.env.P12_PASSWORD || '';
  if (pwdFile) {
    const rawPwd = fs.readFileSync(pwdFile, 'utf-8').trim();
    p12Password = rawPwd.replace(/^(密码|password|pwd)[:：]\s*/i, '').trim();
    logInfo(`从 ${path.basename(pwdFile)} 中智能解析到证书密码: ${p12Password}`);
  } else if (!p12Password) {
    // 交互式询问密码或默认为空
    const readline = (await import('readline')).default;
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    p12Password = await new Promise((resolve) => {
      rl.question('\x1b[33m请输入 P12 证书密码（如无密码请直接按 Enter 回车）: \x1b[0m', (ans) => {
        rl.close();
        resolve(ans.trim());
      });
    });
  }

  logInfo(`找到证书文件: ${path.basename(p12File)}`);
  logInfo(`找到描述文件: ${path.basename(mpFile)}`);

  // 3. 读取描述文件中的 Bundle ID，校验并同步 tauri.conf.json
  const mpContent = fs.readFileSync(mpFile, 'binary');
  const appIDMatch = mpContent.match(/<key>application-identifier<\/key>\s*<string>([^<]+)<\/string>/);
  if (appIDMatch && appIDMatch[1]) {
    const rawAppId = appIDMatch[1];
    // 移除 TeamID 前缀 (如 RH32X4Y4ZN.app.lemon4360.cassava3192 -> app.lemon4360.cassava3192)
    const bundleId = rawAppId.includes('.') ? rawAppId.substring(rawAppId.indexOf('.') + 1) : rawAppId;
    logSuccess(`解析到证书配套 Bundle ID: \x1b[33m${bundleId}\x1b[0m`);

    const tauriConfPath = path.join(rootDir, 'src-tauri', 'tauri.conf.json');
    if (fs.existsSync(tauriConfPath)) {
      const tauriConf = JSON.parse(fs.readFileSync(tauriConfPath, 'utf-8'));
      if (tauriConf.identifier !== bundleId) {
        logInfo(`自动同步 tauri.conf.json identifier 为: ${bundleId}`);
        tauriConf.identifier = bundleId;
        fs.writeFileSync(tauriConfPath, JSON.stringify(tauriConf, null, 2), 'utf-8');
      }
    }
  }

  // 4. 将证书转为 Base64 并上传至 GitHub Secrets
  logInfo('正在自动将证书与描述文件加密配置到 GitHub 仓库 Secrets...');
  const p12Base64 = fs.readFileSync(p12File).toString('base64');
  const mpBase64 = fs.readFileSync(mpFile).toString('base64');

  setGhSecret('BUILD_CERTIFICATE_BASE64', p12Base64);
  setGhSecret('BUILD_PROVISION_PROFILE_BASE64', mpBase64);
  if (p12Password) {
    setGhSecret('P12_PASSWORD', p12Password);
  }
  logSuccess('GitHub Secrets 证书与密码配置完成！');

  // 5. 确保代码已推送到远程
  logInfo('检查本地代码提交状态...');
  const gitStatus = runQuiet('git status --porcelain');
  if (gitStatus) {
    logInfo('发现本地有改动，正在自动提交并推送...');
    // 只提交受控的源码/配置改动，绝不把 dist-ipa、src-tauri/target、
    // gen/apple(每次构建生成的工程)、p12 证书等产物/机密卷进提交。
    run('git add .github/workflows/build-ios.yml scripts/build-ipa.mjs src src-tauri package.json pnpm-lock.yaml vite.config.ts tsconfig.json index.html');
    try {
      run('git commit -m "chore: auto update config and workflows"');
    } catch (e) {}
  }
  logInfo('推送代码至 GitHub 远程仓库...');
  run('git push origin master --force-with-lease || git push origin main --force-with-lease || git push');

  // 6. 触发 GitHub Actions 工作流
  logInfo('正在触发 GitHub Actions 构建工作流 [build-ios.yml]...');
  run('gh workflow run build-ios.yml');

  logSuccess('已成功触发 GitHub Actions 云端构建！');
  logInfo('正在等待并监听云端构建状态...');

  // 7. 稍作等待以获取最新的 run id
  await new Promise(r => setTimeout(r, 4000));
  const runId = runQuiet('gh run list --workflow=build-ios.yml --limit 1 --json databaseId --jq ".[0].databaseId"');

  if (runId) {
    console.log(`\n\x1b[36m▶ 正在跟踪 Action 运行状态 (ID: ${runId})...\x1b[0m`);
    try {
      run(`gh run watch ${runId}`);
    } catch (e) {
      logWarning('构建已触发，可前往 GitHub Actions 查看进度。');
    }

    // 8. 尝试下载打包产物
    logInfo('尝试从云端下载打包生成的 IPA 文件...');
    const outputDir = path.join(rootDir, 'dist-ipa');
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }
    // 旧 .ipa 加时间戳备份，避免 gh download 因文件已存在而失败
    backupExistingIpa(outputDir);
    runQuiet(`gh run download ${runId} -n tauri-ios-ipa -D "${outputDir}" --force`);
    // 判断是否真正拿到产物
    const ipaCount = fs.existsSync(outputDir)
      ? fs.readdirSync(outputDir).filter((f) => /\.ipa$/i.test(f)).length
      : 0;
    if (ipaCount > 0) {
      logSuccess(`IPA 文件已成功下载至: ${outputDir}`);
    } else {
      logWarning(`未能自动下载产物，您可以稍后访问 GitHub 仓库 Actions 页面直接下载。`);
    }
  } else {
    logWarning('可前往 GitHub 仓库 Actions 页面查看实时构建进度与下载产物。');
  }

  console.log('\n\x1b[32m================================================\x1b[0m');
  console.log('\x1b[32m🎉 自动化全流程处理完毕！\x1b[0m');
  console.log('\x1b[32m================================================\x1b[0m');
}

// -------------------------------------------------------------
// 云端 macOS Runner (CI 运行环境)：执行编译、签名与打包
// -------------------------------------------------------------
async function handleCIRunner(rootDir) {
  console.log('\x1b[32m================================================\x1b[0m');
  console.log('\x1b[32m🚀 [CI Runner] 正在执行 macOS 原生编译与签名打包\x1b[0m');
  console.log('\x1b[32m================================================\x1b[0m');

  const outputDir = path.join(rootDir, 'dist-ipa');
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  // 1. 构建前端
  console.log('\n[1/4] 📦 构建前端静态资源...');
  run('pnpm build');

  // 2. 检查或初始化 iOS 项目结构
  console.log('\n[2/4] 🛠️ 检查 Tauri iOS 项目模板...');
  const genAppleDir = path.join(rootDir, 'src-tauri', 'gen', 'apple');
  if (!fs.existsSync(genAppleDir)) {
    logInfo('未检测到 gen/apple，执行 `pnpm tauri ios init` 初始化 iOS 模板...');
    run('pnpm tauri ios init');
  }

  // 3. 证书与钥匙串配置
  console.log('\n[3/4] 🔐 挂载代码签名证书与描述文件...');
  let keychainPath = null;
  let signingIdentity = null;
  let mobileProvisionPath = null;
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tauri-ios-'));

  const p12Base64 = process.env.BUILD_CERTIFICATE_BASE64;
  const p12Password = process.env.P12_PASSWORD || '';
  const ppBase64 = process.env.BUILD_PROVISION_PROFILE_BASE64;
  const keychainPassword = process.env.KEYCHAIN_PASSWORD || 'temp_build_keychain_pwd';

  if (p12Base64 && ppBase64) {
    logSuccess('检测到环境变量中的 Base64 证书与描述文件');
    const certPath = path.join(tempDir, 'certificate.p12');
    mobileProvisionPath = path.join(tempDir, 'embedded.mobileprovision');

    fs.writeFileSync(certPath, Buffer.from(p12Base64, 'base64'));
    fs.writeFileSync(mobileProvisionPath, Buffer.from(ppBase64, 'base64'));

    keychainPath = path.join(tempDir, 'app-signing.keychain-db');
    run(`security create-keychain -p "${keychainPassword}" "${keychainPath}"`);
    run(`security set-keychain-settings -lut 21600 "${keychainPath}"`);
    run(`security unlock-keychain -p "${keychainPassword}" "${keychainPath}"`);
    importP12ToKeychain(certPath, p12Password, keychainPath, tempDir);
    run(`security default-keychain -s "${keychainPath}"`);
    run(`security list-keychain -d user -s "${keychainPath}" $(security list-keychains -d user | tr -d '"')`);
    run(`security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "${keychainPassword}" "${keychainPath}"`);
    run(`security unlock-keychain -p "${keychainPassword}" "${keychainPath}"`);

    signingIdentity = runQuiet(`security find-identity -v -p codesigning "${keychainPath}" | head -n 1 | awk -F '"' '{print $2}'`);
    logSuccess(`解析到签名 Identity: ${signingIdentity}`);
  } else {
    logWarning('未检测到 P12 证书，将打包为未签名 IPA');
  }

  if (mobileProvisionPath) {
    const mpContent = fs.readFileSync(mobileProvisionPath, 'binary');
    const teamMatch = mpContent.match(/<key>TeamIdentifier<\/key>\s*<array>\s*<string>([^<]+)<\/string>/);
    if (teamMatch && teamMatch[1]) {
      process.env.APPLE_DEVELOPMENT_TEAM = teamMatch[1];
      logSuccess(`设置 APPLE_DEVELOPMENT_TEAM: ${teamMatch[1]}`);
    }
    const userProfilesDir = path.join(os.homedir(), 'Library', 'MobileDevice', 'Provisioning Profiles');
    if (!fs.existsSync(userProfilesDir)) {
      fs.mkdirSync(userProfilesDir, { recursive: true });
    }
    fs.copyFileSync(mobileProvisionPath, path.join(userProfilesDir, path.basename(mobileProvisionPath)));
  }

  // 4. 执行 Tauri iOS 编译
  console.log('\n[4/4] 🔨 编译 Tauri iOS 原生工程与打包 IPA...');
  const xcodeProj = findFile(path.join(rootDir, 'src-tauri', 'gen', 'apple'), /\.xcodeproj$/);
  const archivePath = path.join(tempDir, 'tauri-app.xcarchive');

  logInfo('编译 Rust aarch64-apple-ios 原生核心库...');
  // 必须启用 tauri/custom-protocol feature：tauri 据此判定为 release 模式（dev="!custom-protocol"），
  // 否则启动时会去请求 devUrl(http://localhost:1420) 而不是加载嵌入前端资源（tauri cli 构建时会强制注入该 feature）。
  run('cargo build --manifest-path src-tauri/Cargo.toml --target aarch64-apple-ios --release --lib --features tauri/custom-protocol');

  // 将编译出的 Rust 静态库放置到 Xcode 工程期望的 Externals 目录。
  // 原本由 xcode-script 脚本阶段负责（其构建时会生成 libapp.a 到
  // gen/apple/Externals/<arch>/<configuration>/），该阶段已被替换为 echo，
  // 因此需要手动把 cargo 产物复制到位，否则链接器报 `library 'app' not found`。
  {
    const rustLibDir = path.join(rootDir, 'src-tauri', 'target', 'aarch64-apple-ios', 'release');
    if (!fs.existsSync(rustLibDir)) {
      logError(`未找到 Rust 编译产物目录: ${rustLibDir}`);
      process.exit(1);
    }
    const candidates = fs.readdirSync(rustLibDir).filter((f) => /^lib.*\.a$/.test(f));
    const staticLib = candidates.find((f) => f.includes('tauri_app_lib')) || candidates[0];
    if (!staticLib) {
      logError(`未在 ${rustLibDir} 中找到 .a 静态库产物`);
      process.exit(1);
    }
    const externalsDir = path.join(rootDir, 'src-tauri', 'gen', 'apple', 'Externals', 'arm64', 'release');
    fs.mkdirSync(externalsDir, { recursive: true });
    fs.copyFileSync(path.join(rustLibDir, staticLib), path.join(externalsDir, 'libapp.a'));
    logSuccess(`Rust 静态库 ${staticLib} 已放置到 ${path.relative(rootDir, path.join(externalsDir, 'libapp.a'))}`);
  }

  // 优化 Xcode 工程文件：规避 CI 环境下 xcode-script 对 WebSocket 通信的依赖
  const pbxprojPath = findFile(path.join(rootDir, 'src-tauri', 'gen', 'apple'), /project\.pbxproj$/);
  if (pbxprojPath) {
    let pbxContent = fs.readFileSync(pbxprojPath, 'utf-8');
    if (/shellScript = ".*xcode-script.*";/.test(pbxContent)) {
      // 整行替换整个 PBXShellScriptBuildPhase 的 shellScript 值，
      // 避免部分正则替换在 pbxproj 内残留未转义的双引号/分号导致工程文件损坏
      pbxContent = pbxContent.replace(/^\s*shellScript = (".*xcode-script.*");\s*$/gm, '\t\t\tshellScript = "echo Rust code pre-compiled successfully";');
      fs.writeFileSync(pbxprojPath, pbxContent, 'utf-8');
      // 用 plutil 校验替换后的 pbxproj 语法，防止工程文件损坏
      const lintResult = runQuiet(`plutil -lint "${pbxprojPath}"`);
      if (!lintResult.includes('OK')) {
        logError(`pbxproj 替换后语法校验失败: ${lintResult}`);
        process.exit(1);
      }
      logSuccess('已自动解除 Xcode 工程对本地 WebSocket 通信的依赖');
    }
  }

  if (xcodeProj) {
    logInfo('调用 xcodebuild 归档 iOS 原生工程 (-destination "generic/platform=iOS")...');
    runXcodebuild(`xcodebuild archive -project "${xcodeProj}" -scheme tauri-app_iOS -configuration release -destination "generic/platform=iOS" -archivePath "${archivePath}" CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO CODE_SIGN_STYLE=Manual -allowProvisioningUpdates`);
  }

  const appPath = findFile(tempDir, /\.app$/, 'dir') ||
                  findFile(path.join(rootDir, 'src-tauri', 'gen', 'apple'), /\.app$/, 'dir') ||
                  findFile(path.join(rootDir, 'src-tauri', 'target'), /\.app$/, 'dir');

  if (!appPath) {
    logError('未找到编译生成的 .app 目录！');
    process.exit(1);
  }

  logInfo(`找到已编译 App: ${appPath}`);
  const payloadDir = path.join(tempDir, 'Payload');
  fs.mkdirSync(payloadDir, { recursive: true });
  const appName = path.basename(appPath);
  const targetAppDir = path.join(payloadDir, appName);

  run(`cp -R "${appPath}" "${payloadDir}/"`);

  let finalIpaName = 'tauri-app-signed.ipa';

  if (signingIdentity && mobileProvisionPath) {
    logInfo(`正在进行 codesign 递归签名 (Identity: ${signingIdentity})...`);
    fs.copyFileSync(mobileProvisionPath, path.join(targetAppDir, 'embedded.mobileprovision'));

    const provPlistPath = path.join(tempDir, 'provision.plist');
    const entPlistPath = path.join(tempDir, 'entitlements.plist');

    run(`security cms -D -i "${mobileProvisionPath}" > "${provPlistPath}"`);
    run(`/usr/libexec/PlistBuddy -x -c "Print :Entitlements" "${provPlistPath}" > "${entPlistPath}"`);

    const frameworksDir = path.join(targetAppDir, 'Frameworks');
    if (fs.existsSync(frameworksDir)) {
      run(`find "${frameworksDir}" -type f -exec codesign --force --sign "${signingIdentity}" --keychain "${keychainPath}" {} + 2>/dev/null || true`);
    }

    run(`codesign --force --sign "${signingIdentity}" --keychain "${keychainPath}" --entitlements "${entPlistPath}" --timestamp=none "${targetAppDir}"`);
  } else {
    finalIpaName = 'tauri-app-unsigned.ipa';
  }

  const finalIpaPath = path.join(outputDir, finalIpaName);
  if (fs.existsSync(finalIpaPath)) {
    fs.unlinkSync(finalIpaPath);
  }

  run(`cd "${tempDir}" && zip -qry "${finalIpaPath}" Payload`);

  if (keychainPath && fs.existsSync(keychainPath)) {
    runQuiet(`security delete-keychain "${keychainPath}"`);
  }

  logSuccess(`IPA 构建打包成功: ${finalIpaPath}`);
}

async function main() {
  const rootDir = process.cwd();
  const isCI = process.env.CI === 'true' || process.env.GITHUB_ACTIONS === 'true';

  if (isCI) {
    await handleCIRunner(rootDir);
  } else {
    await handleLocalTrigger(rootDir);
  }
}

main().catch((err) => {
  console.error('\n❌ 执行失败:', err);
  process.exit(1);
});
