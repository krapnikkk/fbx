import ByteBuffer from 'bytebuffer';
import * as fs from 'fs'
import * as crypto from 'crypto'
import Pako from 'pako';
const MAGIC = 'Kaydara FBX Binary\x20\x20\x00\x1a\x00';
const fbxVersion = 7400;
const footerZeroes = 120;
const footerCodeSize = 16;
const createTime = new Date();
const fileId = new Uint8Array([0x28, 0xb3, 0x2a, 0xeb, 0xb6, 0x24, 0xcc, 0xc2, 0xbf, 0xc8, 0xb0, 0x2a, 0xa9, 0x2b, 0xfc, 0xf1]);
const sourceId = [0x58, 0xAB, 0xA9, 0xF0, 0x6C, 0xA2, 0xD8, 0x3F, 0x4D, 0x47, 0x49, 0xA3, 0xB4, 0xB2, 0xE7, 0x3D];
const footerId = [0xfa, 0xbc, 0xab, 0x09, 0xd0, 0xc8, 0xd4, 0x66, 0xb1, 0x76, 0xfb, 0x83, 0x1c, 0xf7, 0x26, 0x7e];
const FOOT_MAGIC = [0xF8, 0x5A, 0x8C, 0x6A, 0xDE, 0xF5, 0xD9, 0x7E, 0xEC, 0xE9, 0x0C, 0xE3, 0x75, 0x8F, 0x29, 0x0B];

function generateFileId() {
    let fileId = new Uint8Array(16);
    // node
    crypto.randomBytes(16).copy(fileId);
    // browser
    // crypto.getRandomValues(fileId);
    return fileId;
}

function encryptFooterCode(sourceId, target, size) {
    let c = 64;
    for (let i = 0; i < size; i++) {
        sourceId[i] = (sourceId[i] ^ (c ^ target[i]));
        c = sourceId[i];
    }
}

function getTimeObject(date) {
    return {
        Version: 1000,
        Year: date.getFullYear(),
        Month: date.getMonth() + 1,
        Day: date.getDate(),
        Hour: date.getHours(),
        Minute: date.getMinutes(),
        Second: date.getSeconds(),
        Millisecond: date.getMilliseconds(),
    };

}

function formatDateTime(dateTime) {
    // 确保输入是一个有效的 Date 对象
    if (!(dateTime instanceof Date)) {
        throw new Error('Input must be a Date object');
    }

    // 格式化年、月、日
    const year = dateTime.getFullYear();
    const month = String(dateTime.getMonth() + 1).padStart(2, '0');
    const day = String(dateTime.getDate()).padStart(2, '0');

    // 格式化时、分、秒、毫秒
    const hours = String(dateTime.getHours()).padStart(2, '0');
    const minutes = String(dateTime.getMinutes()).padStart(2, '0');
    const seconds = String(dateTime.getSeconds()).padStart(2, '0');
    const milliseconds = String(dateTime.getMilliseconds()).padStart(3, '0');

    // 拼接格式化后的时间字符串
    return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}:${milliseconds}`;
}
function is2ByteSignedInteger(value) {
    return Number.isInteger(value) && value >= -32768 && value <= 32767;
}
function is4ByteSignedInteger(value) {
    return Number.isInteger(value) && value >= -2147483648 && value <= 2147483647;
}

function is8ByteSignedInteger(value) {
    return Number.isInteger(value) && value >= BigInt(-9223372036854775808) &&
        value <= BigInt(9223372036854775807);
}

function is4ByteSinglePrecisionIEEE754(value) {
    const buffer = new ArrayBuffer(4);
    const view = new DataView(buffer);
    view.setFloat32(0, value);
    return view.getFloat32(0) === value;
}

function is8ByteDoublePrecisionIEEE754(value) {
    const buffer = new ArrayBuffer(8);
    const view = new DataView(buffer);
    view.setFloat64(0, value);
    return view.getFloat64(0) === value;
}

function createColorProperties70(propName, values) {
    return createProperties70(propName, values, "Color", "", "A");
}

function createColorRGBProperties70(propName, values) {
    return createProperties70(propName, values, "ColorRGB", "Color");
}

function createVectorProperties70(propName, values) {
    return createProperties70(propName, values, "Vector", "", "A");
}

function createVector3DProperties70(propName, values) {
    return createProperties70(propName, values, "Vector3D", "Vector");
}

function createIntProperties70(propName, values) {
    return createProperties70(propName, values, "int", "Integer");
}

function createNumberProperties70(propName, values) {
    return createProperties70(propName, values, "Number", "", "A");
}

function createDoubleProperties70(propName, values, flags = "") {
    return createProperties70(propName, values, "double", "Number", flags);
}

function createObjectProperties70(propName, values) {
    return {
        propName,
        propType: "object",
        label: "",
        values
    }
}

function createKTimeProperties70(propName, values) {
    return createProperties70(propName, values, "KTime", "Time");
}

function createKStringProperties70(propName, values = "", flags = "") {
    return createProperties70(propName, values, "KString", flags);
}

function createEnumProperties70(propName, values) {
    return createProperties70(propName, values, "enum");
}

function createBoolProperties70(propName, values) {
    return createProperties70(propName, values ? 1 : 0, "bool");
}

function craeteLclProperties70(propName, values) {
    return createProperties70(propName, values, propName, "", "A");
}

function createCommonProperties70(propName, values, aplha = true) {
    return createProperties70(propName, values, propName, "", aplha ? "A" : "");
}

function createDateTimeProperties70(propName, values) {
    return createProperties70(propName, values, "DateTime");
}

function createCompoundProperties70(propName) {
    return {
        propName,
        propType: "Compound",
        label: "",
        flags: ""
    }
}

function createProperties70(propName, values, propType = "", label = "", flags = "") {
    return {
        propName,
        propType,
        label,
        flags,
        values,
    }

}

class FBXWriter {
    constructor() {
        this.binaryWriter = new ByteBuffer(ByteBuffer.DEFAULT_CAPACITY, ByteBuffer.LITTLE_ENDIAN);
        this.WriteBinaryHeader();
    }

    WriteBinaryHeader() {
        this.binaryWriter.writeString(MAGIC);
        this.binaryWriter.writeUint32(fbxVersion);
    }

    writeNode(label, component, start = 0) {
        let writer = new ByteBuffer(ByteBuffer.DEFAULT_CAPACITY, ByteBuffer.LITTLE_ENDIAN);
        writer.label = label;
        let { nodes, properties, buffers } = component;
        // if(label == "Takes"){debugger}
        let numProperties = this.getPropertyListLen(properties, buffers);

        writer.writeUint32(numProperties)
        let propertyOffset = writer.offset;
        writer.writeUint32(0)
            .writeUint8(label.length)
            .writeString(label);
        let propertyPos = writer.offset;

        let typeCode = "";
        if (Array.isArray(properties)) {
            if (
                properties.includes("KTime")
                ||
                (properties.includes("Scene") && label == "Document")
                ||
                (label == "RootNode")
                ||
                (label == "C" && properties.includes("OO"))
                ||
                (label == "Geometry" || label == "Model" || label == "Material")

            ) {
                typeCode = "L";
            }
            if (
                properties.includes("double")
                ||
                (label == "P" && properties.includes("A"))

            ) {
                typeCode = "D";
            }
        }
        for (let key in properties) {
            let property = properties[key];
            let type = typeof property;
            // console.log(`property:${property}`)

            // "string" | "number" | "bigint" | "boolean" | "symbol" | "undefined" | "object" | "function"
            switch (type) {
                case "boolean":
                    this.writeProperty(writer, "C", property ? 1 : 0);
                    break;
                case "number":
                    // if (is2ByteSignedInteger(property)) {
                    //     this.writeProperty(writer, "Y", property);
                    //     // this.writeProperty(writer, "I", property);
                    //     break;
                    // } else 
                    if (typeCode) {
                        this.writeProperty(writer, typeCode, property);
                        break;
                    } else {
                        if (is4ByteSignedInteger(property)) {
                            this.writeProperty(writer, "I", property);
                            break;
                        } else if (is8ByteSignedInteger(property)) {
                            // debugger
                            this.writeProperty(writer, "L", property);
                            break;
                        } else if (is4ByteSinglePrecisionIEEE754(property)) {
                            this.writeProperty(writer, "F", property);
                            break;
                        } else if (is8ByteDoublePrecisionIEEE754(property)) {
                            this.writeProperty(writer, "D", property);
                            break;
                        } else {
                            throw new Error("Unsupported number type")
                        }
                    }

                case "string":
                    if (property.indexOf("::") > -1) {
                        property = property.split("::").reverse().join("\x00\x01");
                    }
                    this.writeProperty(writer, "S", property);
                    break;
                case "object":
                    let objType = Object.prototype.toString.call(property);
                    if (objType === "[object BigInt]") {
                        // debugger
                        this.writeProperty(writer, "L", property);
                        break;
                    } else if (objType === "[object Uint8Array]") {
                        this.writeProperty(writer, "R", property);
                        break;
                    } else if (objType === "[object Array]") {
                        // debugger
                        for (let i = 0; i < property.length; i++) {
                            this.writeProperty(writer, "D", property[i]);
                        }
                        break;
                    }
                    debugger
                    break;
                default:
                    debugger
                    break;
            }
            // this.writeProperty(writer, key, property);
        }

        if (buffers) {
            let { type, data } = buffers;
            // debugger
            let typeCode = "";
            switch (type) {
                case "float32":
                    typeCode = "f";
                    break
                case "float64":
                    typeCode = "d";
                    break
                case "int32":
                    typeCode = "i";
                    break
                case "int64":
                    typeCode = "l";
                    break
                case "bool":
                    typeCode = "b";
                    break
                default:
                    break
            }
            if (label == "Vertices" || label == "Normals" || label == "UV") {
                typeCode = "d";
            }
            this.writeProperty(writer, typeCode, data);
        }

        let endOffset = writer.offset;
        writer.writeUint32(endOffset - propertyPos, propertyOffset);
        writer.offset = endOffset;

        for (let key in nodes) {
            if (key.indexOf("__ARRAY__") > -1) {
                let type = key.replace("__ARRAY__", "");
                let val = nodes[key];
                delete nodes[key];
                for (let i = 0; i < val.length; i++) {
                    let node = val[i];
                    nodes[`__${type}__${i}`] = node;
                }
            }
        }

        let nodeArr = nodes ? Object.keys(nodes) : [];
        for (let i = 0; i < nodeArr.length; i++) {
            let key = nodeArr[i];
            let node = nodes[key];
            if (key == "properties") {
                continue;
            }
            if (key.indexOf("__") > -1) {
                let [, type] = key.split("__");
                key = type;
            }
            let parentNode = false;
            if (typeof node == "object") {
                if (label == "Properties70") {
                    key = "P";
                    node = { "properties": Object.values(node) };
                } else {
                    if (typeof node['nodes'] == "undefined" && typeof node['properties'] == "undefined" && typeof node['buffers'] == "undefined") {
                        node = { "nodes": node };
                    }
                }
                // need to write property & endOffset
                parentNode = true;
                // console.log(`Parent Node：${key} offset：${start}`);
            } else { // number string
                let obj = Object.create({});
                obj[key] = node;
                node = { "properties": obj };
            }
            let next = parentNode ? writer.offset + start + 4 : writer.offset + start;
            let nodeWriter = this.writeNode(key, node, next);
            let { offset } = nodeWriter;
            let clone = writer.clone();
            clone.append(nodeWriter.slice(0, offset));
            let endOffset = start + clone.offset + 4;
            console.log(endOffset, nodeWriter.label);
            writer.writeUint32(endOffset);
            writer.append(nodeWriter.slice(0, offset));
        }
        if (nodes) {
            let buffer = new Uint8Array(13)
            writer.append(buffer);
        }
        return writer;
    }

    // Primitive Types
    // Y: 2 byte signed Integer
    // C: 1 bit boolean (1: true, 0: false) encoded as the LSB of a 1 Byte value.
    // I: 4 byte signed Integer
    // F: 4 byte single-precision IEEE 754 number
    // D: 8 byte double-precision IEEE 754 number
    // L: 8 byte signed Integer

    // Array types
    // f: Array of 4 byte single-precision IEEE 754 number
    // d: Array of 8 byte double-precision IEEE 754 number
    // l: Array of 8 byte signed Integer
    // i: Array of 4 byte signed Integer
    // b: Array of 1 byte Booleans (always 0 or 1)

    // Special types
    // S: String
    // R: raw binary data

    writeProperty(writer, typeCode, val) {
        writer.writeString(typeCode);
        var write = {
            Y: function (val) { writer.writeInt16(val); },
            C: function (val) { writer.writeByte(val); },
            I: function (val) { writer.writeInt32(val); },
            F: function (val) { writer.writeFloat32(val); },
            D: function (val) { writer.writeFloat64(val); },
            L: function (val) { writer.writeInt64(val); },
            S: function (val) { writer.writeUint32(val.length); writer.writeString(val); },
            R: function (val) { writer.writeUint32(val.length); writer.append(val); },
            f: (val) => { this.writePropertyArray(val, writer, "Float32"); },
            d: (val) => { this.writePropertyArray(val, writer, "Float64"); },
            l: (val) => { this.writePropertyArray(val, writer, "Int64"); },
            i: (val) => { this.writePropertyArray(val, writer, "Int32"); },
            b: (val) => { this.writePropertyArray(val, writer, "Byte"); },
        };
        write[typeCode](val);
    }
    
    writePropertyArray(data, writer, type) {
        writer.writeUint32(data.length);
        let encoding = type.indexOf("Int") > -1 ? 0 : 1;
        writer.writeUint32(encoding);
        let bytebuffer = new globalThis[`${type}Array`](data).buffer;
        let compressedData = encoding ? Pako.deflate(bytebuffer) : bytebuffer;
        writer.writeUint32(compressedData.byteLength);
        writer.append(compressedData);
    }

    writeSection(section, info) {
        let start = this.binaryWriter.offset + 4;
        let node = this.writeNode(section, info, start);
        let { offset, label } = node;
        let clone = this.binaryWriter.clone();
        clone.append(node.slice(0, offset));
        let endOffset = clone.offset + 4;
        console.log(`endOffset:${endOffset} label:${label}`);
        this.binaryWriter.writeUint32(endOffset);
        this.binaryWriter.append(node.slice(0, offset));
    }

    getPropertyListLen(properties, buffers) {
        let len = 0;
        for (let key in properties) {
            let val = properties[key];
            if (Array.isArray(val)) {
                len += val.length;
            } else {
                len += 1;
            }
        }
        if (buffers) {
            len = 1;
        }
        return len;
    }

    writeHeader(header) {
        this.writeSection("FBXHeaderExtension", header);
    }

    writeFileId() {
        this.writeSection("FileId", { properties: [fileId] });
    }

    writeCreationTime() {
        this.writeSection("CreationTime", { properties: ["1970-01-01 10:00:00:000"] });
    }

    writeCreator() {
        this.writeSection("Creator", { properties: ["Blender (stable FBX IO) - 3.6.5 - 5.4.0"] });
    }

    writeGlobalSettings(setting) {
        this.writeSection("GlobalSettings", setting);
    }

    writeDocuments(document) {
        this.writeSection("Documents", document);
    }

    wirteReferences(reference) {
        this.writeSection("References", reference);
    }

    writeDefinitions(definition) {
        this.writeSection("Definitions", definition);
    }

    writeObjects(object) {
        this.writeSection("Objects", object);
    }

    writeConnections(connection) {
        this.writeSection("Connections", connection);
    }

    writeTasks(task) {
        this.writeSection("Takes", task);
    }

    writeBinaryFooter() {
        let nullRecords = new Uint8Array(13);
        this.binaryWriter.append(nullRecords);
        this.binaryWriter.append(new Uint8Array(footerId));
        var position = this.binaryWriter.offset;
        var paddingLength = 16 - (position % 16); // 16 byte alignment
        if (paddingLength == 0) {
            paddingLength = 16;
        }
        paddingLength += 4;

        this.binaryWriter.append(new Uint8Array(paddingLength));
        this.binaryWriter.writeUint32(fbxVersion);
        this.binaryWriter.append(new Uint8Array(120));
        this.binaryWriter.append(new Uint8Array(FOOT_MAGIC));
    }

    save() {
        fbx.writeBinaryFooter()
        try {
            let buffer = this.binaryWriter.slice(0, this.binaryWriter.offset).toBuffer();
            // debugger
            fs.writeFileSync('custom.fbx', buffer);
        } catch (e) {
            console.log(e);
        }
        console.log("Save Success");
    }

}




let fbx = new FBXWriter();
fbx.writeHeader({
    "nodes": {
        "FBXHeaderVersion": 1003,
        "FBXVersion": fbxVersion,
        "EncryptionType": 0,
        // "CreationTimeStamp": getTimeObject(createTime),
        "CreationTimeStamp": {
            Version: 1000,
            Year: 2024,
            Month: 5,
            Day: 25,
            Hour: 15,
            Minute: 20,
            Second: 19,
            Millisecond: 425,
        },
        "Creator": "Blender (stable FBX IO) - 3.6.5 - 5.4.0",
        "SceneInfo": {
            "properties": [
                "SceneInfo::GlobalInfo",
                "UserData"
            ],
            "nodes": {
                "Type": "UserData",
                "Version": 100,
                "MetaData": {
                    "Version": 100,
                    "Title": "",
                    "Subject": "",
                    "Author": "",
                    "Keywords": "",
                    "Revision": "",
                    "Comment": ""
                },
                "Properties70": [
                    createKStringProperties70("DocumentUrl", "/foobar.fbx", "Url"),
                    createKStringProperties70("SrcDocumentUrl", "/foobar.fbx", "Url"),
                    createCompoundProperties70("Original"),
                    createKStringProperties70("Original|ApplicationVendor", "Blender Foundation"),
                    createKStringProperties70("Original|ApplicationName", "Blender (stable FBX IO)"),
                    createKStringProperties70("Original|ApplicationVersion", "3.6.5"),
                    createDateTimeProperties70("Original|DateTime_GMT", "01/01/1970 00:00:00.000"),
                    createKStringProperties70("Original|FileName", "/foobar.fbx"),
                    createCompoundProperties70("LastSaved"),
                    createKStringProperties70("LastSaved|ApplicationVendor", "Blender Foundation"),
                    createKStringProperties70("LastSaved|ApplicationName", "Blender (stable FBX IO)"),
                    createKStringProperties70("LastSaved|ApplicationVersion", "3.6.5"),
                    createDateTimeProperties70("LastSaved|DateTime_GMT", "01/01/1970 00:00:00.000"),
                    createKStringProperties70("Original|ApplicationNativeFile"),
                ]
            }
        }
    }
});
fbx.writeFileId();
fbx.writeCreationTime();
fbx.writeCreator();
fbx.writeGlobalSettings({
    "nodes": {
        "Version": 1000,
        "Properties70": {
            "nodes": [
                createIntProperties70("UpAxis", 1),
                createIntProperties70("UpAxisSign", 1),
                createIntProperties70("FrontAxis", 2),
                createIntProperties70("FrontAxisSign", 1),
                createIntProperties70("CoordAxis", 0),
                createIntProperties70("CoordAxisSign", 1),
                createIntProperties70("OriginalUpAxis", -1),
                createIntProperties70("OriginalUpAxisSign", 1),
                createDoubleProperties70("UnitScaleFactor", 1),
                createDoubleProperties70("OriginalUnitScaleFactor", 1),
                createColorRGBProperties70("AmbientColor", [0, 0, 0]),
                createKStringProperties70("DefaultCamera", "Producer Perspective"),
                {
                    "propName": "TimeMode",
                    "propType": "enum",
                    "label": "",
                    "flags": "",
                    "values": 11,
                },
                createKTimeProperties70("TimeSpanStart", 0),
                createKTimeProperties70("TimeSpanStop", 46186158000),
                createDoubleProperties70("CustomFrameRate", 24)

            ]
        }
    }
});
fbx.writeDocuments({
    "nodes": {
        "Count": 1,
        "Document": {
            "properties": [
                // Math.floor(Date.now() / 10000),
                907313972,
                "Scene",
                "Scene"
            ],
            "nodes": {
                "Properties70": [
                    {
                        "propName": "SourceObject",
                        "propType": "object",
                        "label": "",
                        "flags": "",
                    },
                    createKStringProperties70("ActiveAnimStackName", ""),
                ],
                "RootNode": {
                    "properties": [
                        0
                    ]
                }
            }
        }
    }
});
fbx.wirteReferences({ nodes: [] });
fbx.writeDefinitions({
    "nodes": {
        "Version": 100,
        "Count": 4, // 所有的ObjectType被引用的数量
        "__ARRAY__ObjectType": [
            {
                "properties": [
                    "GlobalSettings"
                ],
                "nodes": {
                    "Count": 1
                }
            },
            {
                "properties": [
                    "Geometry"
                ],
                "nodes": {
                    "Count": 1,
                    "PropertyTemplate": {
                        "properties": ["FbxMesh"],
                        "nodes": {
                            "Properties70": [
                                createColorRGBProperties70("Color", [0.8, 0.8, 0.8]),
                                createVector3DProperties70("BBoxMin", [0, 0, 0]),
                                createVector3DProperties70("BBoxMax", [0, 0, 0]),
                                createBoolProperties70("Primary Visibility", 1),
                                createBoolProperties70("Casts Shadows", 1),
                                createBoolProperties70("Receive Shadows", 1),
                            ]
                        }
                    }
                }
            },
            {
                "properties": [
                    "Model"
                ],
                "nodes": {
                    "Count": 1,
                    "PropertyTemplate": {
                        "properties": ["FbxNode"],
                        "nodes": {
                            "Properties70": [
                                createEnumProperties70("QuaternionInterpolate", 0),
                                createVector3DProperties70("RotationOffset", [0, 0, 0]),
                                createVector3DProperties70("RotationPivot", [0, 0, 0]),
                                createVector3DProperties70("ScalingOffset", [0, 0, 0]),
                                createVector3DProperties70("ScalingPivot", [0, 0, 0]),
                                createBoolProperties70("TranslationActive", false),
                                createVector3DProperties70("TranslationMin", [0, 0, 0]),
                                createVector3DProperties70("TranslationMax", [0, 0, 0]),
                                createBoolProperties70("TranslationMinX", false),
                                createBoolProperties70("TranslationMinY", false),
                                createBoolProperties70("TranslationMinZ", false),
                                createBoolProperties70("TranslationMaxX", false),
                                createBoolProperties70("TranslationMaxY", false),
                                createBoolProperties70("TranslationMaxZ", false),
                                createEnumProperties70("RotationOrder", 0),
                                createBoolProperties70("RotationSpaceForLimitOnly", false),
                                createDoubleProperties70("RotationStiffnessX", 0),
                                createDoubleProperties70("RotationStiffnessY", 0),
                                createDoubleProperties70("RotationStiffnessZ", 0),
                                createDoubleProperties70("AxisLen", 10),
                                createVector3DProperties70("PreRotation", [0, 0, 0]),
                                createVector3DProperties70("PostRotation", [0, 0, 0]),
                                createBoolProperties70("RotationActive", false),
                                createVector3DProperties70("RotationMin", [0, 0, 0]),
                                createVector3DProperties70("RotationMax", [0, 0, 0]),
                                createBoolProperties70("RotationMinX", false),
                                createBoolProperties70("RotationMinY", false),
                                createBoolProperties70("RotationMinZ", false),
                                createBoolProperties70("RotationMaxX", false),
                                createBoolProperties70("RotationMaxY", false),
                                createBoolProperties70("RotationMaxZ", false),
                                createEnumProperties70("InheritType", 0),
                                createBoolProperties70("ScalingActive", false),
                                createVector3DProperties70("ScalingMin", [0, 0, 0]),
                                createVector3DProperties70("ScalingMax", [1, 1, 1]),
                                createBoolProperties70("ScalingMinX", false),
                                createBoolProperties70("ScalingMinY", false),
                                createBoolProperties70("ScalingMinZ", false),
                                createBoolProperties70("ScalingMaxX", false),
                                createBoolProperties70("ScalingMaxY", false),
                                createBoolProperties70("ScalingMaxZ", false),
                                createVector3DProperties70("GeometricTranslation", [0, 0, 0]),
                                createVector3DProperties70("GeometricRotation", [0, 0, 0]),
                                createVector3DProperties70("GeometricScaling", [1, 1, 1]),
                                createDoubleProperties70("MinDampRangeX", 0),
                                createDoubleProperties70("MinDampRangeY", 0),
                                createDoubleProperties70("MinDampRangeZ", 0),
                                createDoubleProperties70("MaxDampRangeX", 0),
                                createDoubleProperties70("MaxDampRangeY", 0),
                                createDoubleProperties70("MaxDampRangeZ", 0),
                                createDoubleProperties70("MinDampStrengthX", 0),
                                createDoubleProperties70("MinDampStrengthY", 0),
                                createDoubleProperties70("MinDampStrengthZ", 0),
                                createDoubleProperties70("MaxDampStrengthX", 0),
                                createDoubleProperties70("MaxDampStrengthY", 0),
                                createDoubleProperties70("MaxDampStrengthZ", 0),
                                createDoubleProperties70("PreferedAngleX", 0),
                                createDoubleProperties70("PreferedAngleY", 0),
                                createDoubleProperties70("PreferedAngleZ", 0),
                                createObjectProperties70("LookAtProperty", ""),
                                createObjectProperties70("UpVectorProperty", ""),
                                createBoolProperties70("Show", true),
                                createBoolProperties70("NegativePercentShapeSupport", true),
                                createIntProperties70("DefaultAttributeIndex", -1),
                                createBoolProperties70("Freeze", false),
                                createBoolProperties70("LODBox", false),
                                createCommonProperties70("Lcl Translation", [0, 0, 0]),
                                createCommonProperties70("Lcl Rotation", [0, 0, 0]),
                                createCommonProperties70("Lcl Scaling", [1, 1, 1]),
                                createCommonProperties70("Visibility", 1),
                                createCommonProperties70("Visibility Inheritance", 1, false),
                            ]
                        }
                    }
                }
            },
            {
                "properties": [
                    "Material"
                ],
                "nodes": {
                    "Count": 1,
                    "PropertyTemplate": {
                        "properties": ["FbxSurfacePhong"],
                        "nodes": {
                            "Properties70": [
                                createKStringProperties70("ShadingModel", "Phong"),
                                createBoolProperties70("MultiLayer", false),
                                createColorProperties70("EmissiveColor", [0, 0, 0]),
                                createNumberProperties70("EmissiveFactor", 1),
                                createColorProperties70("AmbientColor", [0.2, 0.2, 0.2]),
                                createNumberProperties70("AmbientFactor", 1),
                                createColorProperties70("DiffuseColor", [0.8, 0.8, 0.8]),
                                createNumberProperties70("DiffuseFactor", 1),
                                createColorProperties70("TransparentColor", [0, 0, 0]),
                                createNumberProperties70("TransparencyFactor", 0),
                                createNumberProperties70("Opacity", 1),
                                createVector3DProperties70("NormalMap", [0, 0, 0]),
                                createVector3DProperties70("Bump", [0, 0, 0]),
                                createDoubleProperties70("BumpFactor", 1),
                                createColorRGBProperties70("DisplacementColor", [0, 0, 0]),
                                createDoubleProperties70("DisplacementFactor", 1),
                                createColorRGBProperties70("VectorDisplacementColor", [0, 0, 0]),
                                createDoubleProperties70("VectorDisplacementFactor", 1),
                                createColorProperties70("SpecularColor", [0.2, 0.2, 0.2]),
                                createNumberProperties70("SpecularFactor", 1),
                                createNumberProperties70("Shininess", 20),
                                createNumberProperties70("ShininessExponent", 20),
                                createColorProperties70("ReflectionColor", [0, 0, 0]),
                                createNumberProperties70("ReflectionFactor", 1),
                            ]
                        }
                    }
                }
            }
        ]
    }
});
fbx.writeObjects({
    "nodes": {
        "Geometry": {
            "properties": [
                468857135,
                "Geometry::Cube",
                "Mesh"
            ],
            "nodes": {
                "Properties70": [],
                "GeometryVersion": 124,
                "Vertices": {
                    "buffers": {
                        "data": [
                            1,
                            1,
                            1,
                            1,
                            1,
                            -1,
                            1,
                            -1,
                            1,
                            1,
                            -1,
                            -1,
                            -1,
                            1,
                            1,
                            -1,
                            1,
                            -1,
                            -1,
                            -1,
                            1,
                            -1,
                            -1,
                            -1
                        ],
                        "type": "float32"
                    }
                },
                "PolygonVertexIndex": {
                    "buffers": {
                        "data": [
                            0,
                            4,
                            6,
                            -3,
                            3,
                            2,
                            6,
                            -8,
                            7,
                            6,
                            4,
                            -6,
                            5,
                            1,
                            3,
                            -8,
                            1,
                            0,
                            2,
                            -4,
                            5,
                            4,
                            0,
                            -2
                        ], "type": "int32"
                    }
                },
                "Edges": {
                    "buffers": {
                        "data": [
                            0,
                            1,
                            2,
                            3,
                            4,
                            6,
                            7,
                            10,
                            11,
                            12,
                            13,
                            16
                        ], "type": "int32"
                    }
                },
                "LayerElementNormal": {
                    "properties": [0],
                    "nodes": {
                        "Version": 101,
                        "Name": "",
                        "MappingInformationType": "ByPolygonVertex",
                        "ReferenceInformationType": "Direct",
                        "Normals": {
                            "buffers": {
                                "data": [
                                    0,
                                    0,
                                    1,
                                    0,
                                    0,
                                    1,
                                    0,
                                    0,
                                    1,
                                    0,
                                    0,
                                    1,
                                    0,
                                    -1,
                                    0,
                                    0,
                                    -1,
                                    0,
                                    0,
                                    -1,
                                    0,
                                    0,
                                    -1,
                                    0,
                                    -1,
                                    0,
                                    0,
                                    -1,
                                    0,
                                    0,
                                    -1,
                                    0,
                                    0,
                                    -1,
                                    0,
                                    0,
                                    0,
                                    0,
                                    -1,
                                    0,
                                    0,
                                    -1,
                                    0,
                                    0,
                                    -1,
                                    0,
                                    0,
                                    -1,
                                    1,
                                    0,
                                    0,
                                    1,
                                    0,
                                    0,
                                    1,
                                    0,
                                    0,
                                    1,
                                    0,
                                    0,
                                    0,
                                    1,
                                    0,
                                    0,
                                    1,
                                    0,
                                    0,
                                    1,
                                    0,
                                    0,
                                    1,
                                    0
                                ], "type": "float32"
                            }
                        },
                    }
                },
                "LayerElementUV": {
                    "properties": [0],
                    "nodes": {
                        "Version": 101,
                        "Name": "UVMap",
                        "MappingInformationType": "ByPolygonVertex",
                        "ReferenceInformationType": "IndexToDirect",
                        "UV": {
                            "buffers": {
                                "data": [
                                    0.375,
                                    0,
                                    0.625,
                                    0,
                                    0.375,
                                    0.25,
                                    0.625,
                                    0.25,
                                    0.125,
                                    0.5,
                                    0.375,
                                    0.5,
                                    0.625,
                                    0.5,
                                    0.875,
                                    0.5,
                                    0.125,
                                    0.75,
                                    0.375,
                                    0.75,
                                    0.625,
                                    0.75,
                                    0.875,
                                    0.75,
                                    0.375,
                                    1,
                                    0.625,
                                    1
                                ], "type": "float32"
                            }
                        },
                        "UVIndex": {
                            "buffers": {
                                "data": [6,
                                    7,
                                    11,
                                    10,
                                    9,
                                    10,
                                    13,
                                    12,
                                    0,
                                    1,
                                    3,
                                    2,
                                    4,
                                    5,
                                    9,
                                    8,
                                    5,
                                    6,
                                    10,
                                    9,
                                    2,
                                    3,
                                    6,
                                    5], "type": "int32"
                            }
                        }
                    }
                },
                "LayerElementMaterial": {
                    "properties": [0],
                    "nodes": {
                        "Version": 101,
                        "Name": "",
                        "MappingInformationType": "AllSame",
                        "ReferenceInformationType": "IndexToDirect",
                        "Materials": {
                            "buffers": {
                                "data": [0], "type": "int32"
                            }
                        }
                    }
                },
                "Layer": {
                    "properties": [0],
                    "nodes": {
                        "Version": 100,
                        "__ARRAY__LayerElement": [
                            {
                                "nodes": {
                                    "Type": {
                                        "properties": ["LayerElementNormal"]
                                    },
                                    "TypedIndex": {
                                        "properties": [0]
                                    }
                                }
                            },
                            {
                                "nodes": {
                                    "Type": {
                                        "properties": ["LayerElementUV"]
                                    },
                                    "TypedIndex": {
                                        "properties": [0]
                                    }
                                }
                            },
                            {
                                "nodes": {
                                    "Type": {
                                        "properties": ["LayerElementMaterial"]
                                    },
                                    "TypedIndex": {
                                        "properties": [0]
                                    }
                                }
                            }
                        ]
                    }
                }
            }
        },
        "Model": {
            "properties": [
                370274723,
                "Model::Cube",
                "Mesh"
            ],
            "nodes": {
                "Version": 232,
                "Properties70": [
                    craeteLclProperties70("Lcl Rotation", [-90.00000933466734, 0, 0]),
                    craeteLclProperties70("Lcl Scaling", [100, 100, 100]),
                    createIntProperties70("DefaultAttributeIndex", 0),
                    createEnumProperties70("InheritType", 1)
                ],
                "MultiLayer": 0,
                "MultiTake": 0,
                "Shading": {
                    "properties": [true]
                },
                "Culling": {
                    "properties": ["CullingOff"]
                }
            }
        },
        "Material": {
            "properties": [
                178641477,
                "Material::Material",
                ""
            ],
            "nodes": {
                "Version": 102,
                "ShadingModel": "Phong",
                "MultiLayer": 0,
                "Properties70": [
                    createColorProperties70("DiffuseColor", [0.800000011920929, 0.800000011920929, 0.800000011920929]),
                    createColorProperties70("AmbientColor", [0.05087608844041824, 0.05087608844041824, 0.05087608844041824]),
                    createNumberProperties70("AmbientFactor", 0),
                    createDoubleProperties70("BumpFactor", 0),
                    createColorProperties70("SpecularColor", [0.800000011920929, 0.800000011920929, 0.800000011920929]),
                    createNumberProperties70("SpecularFactor", 0.25),
                    createNumberProperties70("Shininess", 25),
                    createNumberProperties70("ShininessExponent", 25),
                    createColorProperties70("ReflectionColor", [0.800000011920929, 0.800000011920929, 0.800000011920929]),
                    createNumberProperties70("ReflectionFactor", 0),
                ]
            }
        }
    }
});
fbx.writeConnections({
    "nodes": {
        "__ARRAY__C": [
            {
                "properties": [
                    "OO",
                    370274723,
                    0
                ]
            },
            {
                "properties": [
                    "OO",
                    468857135,
                    370274723
                ]
            },
            {
                "properties": [
                    "OO",
                    178641477,
                    370274723
                ]
            }
        ]
    }
});
fbx.writeTasks({
    "nodes": {
        "Current": ""
    }
});
fbx.save();