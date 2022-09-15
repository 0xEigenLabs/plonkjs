const fs = require("fs")
const path = require("path");
module.exports.read_file = function read_file(name) {
  let filename = "./tests";
  if (name == "circuit") {
    filename = path.join(filename, "multiplier.r1cs");
  } else if (name == "wtns") {
    filename = path.join(filename, "./witness.wtns");
  } else if (name == "key") {
    filename = path.join(filename, "./setup_2^10.key");
  } else {
    throw new Error("Invalid filename")
  }

  console.log(filename);
  const content = fs.readFileSync(filename);
  return content.toJSON().data;
}
