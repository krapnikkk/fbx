import * as fs from 'fs'
import * as FBXParser from 'fbx-parser'
const { parseBinary, parseText } = FBXParser;
// const file = 'cube-single'
const file = 'custom'
let fbx;
try {
  // try binary file encoding
  fbx = parseBinary(fs.readFileSync(`${file}.fbx`))
} catch (e) {
  console.log(e);
  debugger

  // try text file encoding
  fbx = parseText(fs.readFileSync(file, 'utf-8'))
}
// debugger
console.log(fbx);
fs.writeFileSync(`${file}.json`, JSON.stringify(fbx, null, 2))