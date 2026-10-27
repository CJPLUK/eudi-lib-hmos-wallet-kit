import { appTasks } from '@ohos/hvigor-ohos-plugin';
import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';

// Auto-fetch sibling TPC deps (transitive closure) when missing; no-op in a
// shared workspace/shell third_party. cjpm uses ../../<dep>.
(function syncSiblingDeps() {
  const DEPS = [
    { name: 'eudi_lib_cbor', url: 'https://github.com/CJPLUK/eudi-lib-hmos-cbor', ref: 'v0.1.0' },
    { name: 'eudi_lib_core_crypto', url: 'https://github.com/CJPLUK/eudi-lib-hmos-core-crypto', ref: 'v0.1.0' },
    { name: 'eudi_lib_jose', url: 'https://github.com/CJPLUK/eudi-lib-hmos-jose', ref: 'v0.1.0' },
    { name: 'eudi_lib_x509', url: 'https://github.com/CJPLUK/eudi-lib-hmos-x509', ref: 'v0.1.0' },
    { name: 'eudi_lib_statium', url: 'https://github.com/CJPLUK/eudi-lib-hmos-statium', ref: 'v0.1.0' },
    { name: 'eudi_lib_mdoc_data_model', url: 'https://github.com/CJPLUK/eudi-lib-hmos-mdoc-data-model', ref: 'v0.1.0' },
    { name: 'eudi_lib_sdjwt', url: 'https://github.com/CJPLUK/eudi-lib-hmos-sdjwt', ref: 'v0.1.0' },
    { name: 'eudi_lib_mdoc_security', url: 'https://github.com/CJPLUK/eudi-lib-hmos-mdoc-security', ref: 'v0.1.0' },
    { name: 'eudi_lib_mdoc_transfer', url: 'https://github.com/CJPLUK/eudi-lib-hmos-mdoc-transfer', ref: 'v0.1.0' },
    { name: 'eudi_lib_wallet_storage', url: 'https://github.com/CJPLUK/eudi-lib-hmos-wallet-storage', ref: 'v0.1.0' },
    { name: 'eudi_lib_openid4vp_vci', url: 'https://github.com/CJPLUK/eudi-lib-hmos-openid4vp-vci', ref: 'v0.1.0' },
  ];
  const root = path.resolve(__dirname, '..');
  for (const d of DEPS) {
    const dst = path.join(root, d.name);
    if (fs.existsSync(dst)) continue;
    try {
      console.log(`[deps] cloning ${d.name} -> ${dst}`);
      execSync(`git clone --quiet "${d.url}" "${dst}"`, { stdio: 'inherit' });
      execSync(`git -C "${dst}" fetch --quiet --tags`, { stdio: 'inherit' });
      execSync(`git -C "${dst}" checkout --quiet ${d.ref}`, { stdio: 'inherit' });
    } catch (e) { console.error(`[deps] failed ${d.name}: ${e}`); }
  }
})();

export default { system: appTasks, plugins: [] }
