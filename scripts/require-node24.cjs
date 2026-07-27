const major = Number(process.versions.node.split(".")[0]);

if (major !== 24) {
  console.error(`PolyScan bundles must be built with Node 24; received ${process.version}.`);
  process.exit(1);
}
