// ==================== Classical Algorithms ====================

// Caesar Cipher
function caesarEncrypt(text, shift) {
  return text.split('').map(char => {
    if (/[a-z]/i.test(char)) {
      let code = char.charCodeAt(0);
      let base = (code >= 65 && code <= 90) ? 65 : 97;
      return String.fromCharCode(((code - base + shift) % 26) + base);
    }
    return char;
  }).join('');
}
function caesarDecrypt(text, shift) {
  return caesarEncrypt(text, (26 - shift) % 26);
}

// Monoalphabetic Cipher
const monoKey = "QWERTYUIOPASDFGHJKLZXCVBNM"; 
function monoEncrypt(text) {
  return text.toUpperCase().replace(/[A-Z]/g, c => monoKey[c.charCodeAt(0)-65]);
}
function monoDecrypt(text) {
  return text.toUpperCase().replace(/[A-Z]/g, c => 
    String.fromCharCode(monoKey.indexOf(c) + 65));
}

// Vigenere Cipher
function vigenereEncrypt(text, key) {
  key = key.toUpperCase();
  let result = "", k = 0;
  for (let ch of text) {
    if (/[a-z]/i.test(ch)) {
      let base = (ch === ch.toUpperCase()) ? 65 : 97;
      result += String.fromCharCode(
        (ch.charCodeAt(0)-base + (key[k%key.length].charCodeAt(0)-65))%26 + base
      );
      k++;
    } else result += ch;
  }
  return result;
}
function vigenereDecrypt(text, key) {
  key = key.toUpperCase();
  let result = "", k = 0;
  for (let ch of text) {
    if (/[a-z]/i.test(ch)) {
      let base = (ch === ch.toUpperCase()) ? 65 : 97;
      result += String.fromCharCode(
        (ch.charCodeAt(0)-base - (key[k%key.length].charCodeAt(0)-65) + 26)%26 + base
      );
      k++;
    } else result += ch;
  }
  return result;
}

// Hill Cipher (2x2 fixed matrix [[3,3],[2,5]])
function hillEncrypt(text, keyMatrix) {
  text = text.replace(/[^A-Z]/gi, '').toUpperCase();
  if (text.length % 2 !== 0) text += "X";
  let result = "";
  for (let i=0; i<text.length; i+=2) {
    let a = text.charCodeAt(i)-65, b = text.charCodeAt(i+1)-65;
    let x = (keyMatrix[0][0]*a + keyMatrix[0][1]*b) % 26;
    let y = (keyMatrix[1][0]*a + keyMatrix[1][1]*b) % 26;
    result += String.fromCharCode(x+65) + String.fromCharCode(y+65);
  }
  return result;
}
function hillDecrypt(text, keyMatrix) {
  const inv = [[15,17],[20,9]]; // inverse matrix mod 26 for [[3,3],[2,5]]
  let result = "";
  for (let i=0; i<text.length; i+=2) {
    let a = text.charCodeAt(i)-65, b = text.charCodeAt(i+1)-65;
    let x = (inv[0][0]*a + inv[0][1]*b) % 26;
    let y = (inv[1][0]*a + inv[1][1]*b) % 26;
    result += String.fromCharCode(x+65) + String.fromCharCode(y+65);
  }
  return result;
}

// Playfair Cipher
function buildPlayfairTable(key) {
  key = key.toUpperCase().replace(/J/g,"I");
  let table = [...new Set((key+"ABCDEFGHIKLMNOPQRSTUVWXYZ").split(''))];
  return table;
}
function playfairEncrypt(text, key) {
  let table = buildPlayfairTable(key);
  text = text.toUpperCase().replace(/J/g,"I").replace(/[^A-Z]/g,"");
  let pairs = [];
  for (let i=0; i<text.length; i+=2) {
    let a = text[i], b = text[i+1] || "X";
    if (a === b) { pairs.push([a, "X"]); i--; }
    else pairs.push([a, b]);
  }
  let result = "";
  for (let [a,b] of pairs) {
    let ai=table.indexOf(a), bi=table.indexOf(b);
    let r1=Math.floor(ai/5), c1=ai%5, r2=Math.floor(bi/5), c2=bi%5;
    if (r1===r2) result+=table[r1*5+(c1+1)%5]+table[r2*5+(c2+1)%5];
    else if (c1===c2) result+=table[((r1+1)%5)*5+c1]+table[((r2+1)%5)*5+c2];
    else result+=table[r1*5+c2]+table[r2*5+c1];
  }
  return result;
}
function playfairDecrypt(text, key) {
  let table = buildPlayfairTable(key);
  let result = "";
  for (let i=0; i<text.length; i+=2) {
    let a=table.indexOf(text[i]), b=table.indexOf(text[i+1]);
    let r1=Math.floor(a/5), c1=a%5, r2=Math.floor(b/5), c2=b%5;
    if (r1===r2) result+=table[r1*5+(c1+4)%5]+table[r2*5+(c2+4)%5];
    else if (c1===c2) result+=table[((r1+4)%5)*5+c1]+table[((r2+4)%5)*5+c2];
    else result+=table[r1*5+c2]+table[r2*5+c1];
  }
  return result;
}

// ==================== Modern Algorithms ====================
function aesEncrypt(text, key) { return CryptoJS.AES.encrypt(text, key).toString(); }
function aesDecrypt(text, key) {
  let bytes = CryptoJS.AES.decrypt(text, key);
  return bytes.toString(CryptoJS.enc.Utf8) || "Invalid Key!";
}
function desEncrypt(text, key) { return CryptoJS.DES.encrypt(text, key).toString(); }
function desDecrypt(text, key) {
  let bytes = CryptoJS.DES.decrypt(text, key);
  return bytes.toString(CryptoJS.enc.Utf8) || "Invalid Key!";
}
// Simple RSA Simulation
function rsaEncrypt(text, key) { return btoa(text + "::" + key); }
function rsaDecrypt(text, key) {
  let decoded = atob(text).split("::");
  return decoded[1] === key ? decoded[0] : "Invalid Key!";
}

// ==================== UI with Key Validation ====================
function requiresKey(algo) {
  return ["caesar","polyalpha","playfair","aes","des","rsa"].includes(algo);
}

function toggleKeyField() {
  let algo = document.getElementById("algorithm").value;
  document.getElementById("keyContainer").classList.toggle("hidden", !requiresKey(algo));
}

function encryptText() {
  let text = document.getElementById("plaintext").value;
  let key = document.getElementById("key").value;
  let algo = document.getElementById("algorithm").value;
  let result="";

  if (requiresKey(algo) && !key) {
    alert("Please enter a key for " + algo.toUpperCase() + " cipher!");
    return;
  }

  switch(algo) {
    case "caesar": result = caesarEncrypt(text, parseInt(key)||3); break;
    case "monoalpha": result = monoEncrypt(text); break;
    case "polyalpha": result = vigenereEncrypt(text,key); break;
    case "hill": result = hillEncrypt(text, [[3,3],[2,5]]); break;
    case "playfair": result = playfairEncrypt(text,key); break;
    case "aes": result = aesEncrypt(text,key); break;
    case "des": result = desEncrypt(text,key); break;
    case "rsa": result = rsaEncrypt(text,key); break;
  }
  document.getElementById("result").value = result;
}

function decryptText() {
  let text = document.getElementById("result").value;  
  let key = document.getElementById("key").value;
  let algo = document.getElementById("algorithm").value;
  let result="";

  if (requiresKey(algo) && !key) {
    alert("Please enter a key for " + algo.toUpperCase() + " cipher!");
    return;
  }

  switch(algo) {
    case "caesar": result = caesarDecrypt(text, parseInt(key)||3); break;
    case "monoalpha": result = monoDecrypt(text); break;
    case "polyalpha": result = vigenereDecrypt(text,key); break;
    case "hill": result = hillDecrypt(text, [[3,3],[2,5]]); break;
    case "playfair": result = playfairDecrypt(text,key); break;
    case "aes": result = aesDecrypt(text,key); break;
    case "des": result = desDecrypt(text,key); break;
    case "rsa": result = rsaDecrypt(text,key); break;
    default: result = "Decrypt not implemented for this cipher!";
  }
  document.getElementById("result").value = result;
}

function saveFile() {
  let text = document.getElementById("result").value;
  let blob = new Blob([text], { type: "text/plain" });
  let link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = "output.txt";
  link.click();
}

// ==================== Clear Button ====================
function clearFields() {
  document.getElementById("plaintext").value = "";
  document.getElementById("key").value = "";
  document.getElementById("result").value = "";
  document.getElementById("algorithm").selectedIndex = 0;
  toggleKeyField();
}
