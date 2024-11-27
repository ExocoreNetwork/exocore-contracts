const fs = require('fs');
const { getStorageUpgradeReport } = require('@openzeppelin/upgrades-core');

// Mapping of deployed and compiled file names
const fileMappings = [
  { before: 'Bootstrap.deployed.json', after: 'Bootstrap.compiled.json' },
  { before: 'ClientChainGateway.deployed.json', after: 'ClientChainGateway.compiled.json' },
  { before: 'Vault.deployed.json', after: 'Vault.compiled.json' },
  { before: 'RewardVault.deployed.json', after: 'RewardVault.compiled.json' },
  { before: 'ExoCapsule.deployed.json', after: 'ExoCapsule.compiled.json' },
  { before: 'ExocoreGateway.base.json', after: 'ExocoreGateway.compiled.json' },
  { before: 'Bootstrap.compiled.json', after: 'ClientChainGateway.compiled.json' },
];

// Loop through each mapping, load JSON files, and run the comparison
fileMappings.forEach(({ before, after }) => {
  console.log(`🔍 Comparing ${before} and ${after}...`);
  try {
    // Check if both files exist and exit silently if not
    if (!fs.existsSync(before)) {
      console.log(`⚠️ Skipping: ${before} does not exist.`);
      return;
    }
    if (!fs.existsSync(after)) {
      console.log(`⚠️ Skipping: ${after} does not exist.`);
      return;
    }
    // Load the JSON files
    const deployedData = JSON.parse(fs.readFileSync(before, 'utf8'));
    const compiledData = JSON.parse(fs.readFileSync(after, 'utf8'));

    // Run the storage upgrade comparison
    const report = getStorageUpgradeReport(deployedData, compiledData, { unsafeAllowCustomTypes: true });

    // Print the report if issues are found
    if (!report.ok) {
      console.log(`⚠️ Issues found in ${before} and ${after}:`);
      console.log(report.explain());
      process.exitCode = 1;
    } else {
      console.log(`✅ No issues detected between ${before} and ${after}.`);
    }
  } catch (error) {
    console.error(`❌ Error processing ${before} or ${after}: ${error.message}`);
    process.exitCode = 1;
  }
});
