/**
 * Jest configuration.
 *
 * cdk.out is excluded from both test discovery and Haste module resolution.
 * `cdk synth` copies the lambda/ sources (including their package.json files)
 * into cdk.out/asset.*, which otherwise collide with the originals under
 * lambda/ and trigger "Haste module naming collision" errors.
 */
module.exports = {
  testEnvironment: "node",
  testPathIgnorePatterns: ["/node_modules/", "/cdk.out/"],
  modulePathIgnorePatterns: ["/cdk.out/"],
  coveragePathIgnorePatterns: ["/node_modules/", "/cdk.out/"],
};
