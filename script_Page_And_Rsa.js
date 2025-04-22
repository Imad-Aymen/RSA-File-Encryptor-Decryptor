    // PEM <-> CryptoKey Conversion
    async function importPublicKey(pem) {
      const b64 = pem.replace(/-----(BEGIN|END) PUBLIC KEY-----/g, '').replace(/\s+/g, '');
      const der = Uint8Array.from(atob(b64), c=>c.charCodeAt(0));
      return crypto.subtle.importKey(
        'spki', der.buffer, {name:'RSA-OAEP', hash:'SHA-256'}, true, ['encrypt']
      );
    }
    async function importPrivateKey(pem) {
      const b64 = pem.replace(/-----(BEGIN|END) PRIVATE KEY-----/g, '').replace(/\s+/g, '');
      const der = Uint8Array.from(atob(b64), c=>c.charCodeAt(0));
      return crypto.subtle.importKey(
        'pkcs8', der.buffer, {name:'RSA-OAEP', hash:'SHA-256'}, true, ['decrypt']
      );
    }
    async function exportPublicKey(key) {
      const spki = await crypto.subtle.exportKey('spki', key);
      const b64 = btoa(String.fromCharCode(...new Uint8Array(spki)));
      return `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
    }
    async function exportPrivateKey(key) {
      const pkcs8 = await crypto.subtle.exportKey('pkcs8', key);
      const b64 = btoa(String.fromCharCode(...new Uint8Array(pkcs8)));
      return `-----BEGIN PRIVATE KEY-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----`;
    }
    // Key Generation
    async function generateKeys() {
      showMsg("Generating RSA-2048 key pair, please wait...");
      let keypair = await crypto.subtle.generateKey(
        { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: "SHA-256" },
        true,
        ["encrypt", "decrypt"]
      );
      document.getElementById('pubKey').value = await exportPublicKey(keypair.publicKey);
      document.getElementById('privKey').value = await exportPrivateKey(keypair.privateKey);
      showMsg("Keys generated!");
    }
    // Password-based AES key
    async function getAesKey(password, rawAes) {
      if (!password) return rawAes;
      let enc = new TextEncoder().encode(password);
      let pwKey = await crypto.subtle.importKey("raw", enc, "PBKDF2", false, ["deriveKey"]);
      let salt = new Uint8Array(16);
      crypto.getRandomValues(salt);
      let key = await crypto.subtle.deriveKey(
        {name:"PBKDF2",salt,iterations:100000,hash:"SHA-256"},
        pwKey,
        {name:"AES-GCM",length:256},
        true,
        ["encrypt","decrypt"]
      );
      let raw = await crypto.subtle.exportKey('raw', key);
      let combined = new Uint8Array(rawAes.byteLength);
      for(let i=0;i<rawAes.byteLength;i++) combined[i]=new Uint8Array(rawAes)[i]^raw[i%raw.length];
      return combined.buffer;
    }
    // File Encryption
    async function encryptFile() {
  clearMsg();
  const fileInput = document.getElementById('fileInput');
  const pubPem = document.getElementById('pubKey').value.trim();
  
  if (!fileInput.files.length) return showMsg('Please select a file to encrypt.', true);
  if (!pubPem.includes('PUBLIC KEY')) return showMsg('Please provide a valid public key.', true);
  
  const file = fileInput.files[0];
  let publicKey;
  
  try {
    publicKey = await importPublicKey(pubPem);
  } catch (e) {
    return showMsg('Failed to parse public key.', true);
  }

  const data = new Uint8Array(await file.arrayBuffer());
  
  // Encrypt the file data with RSA
  let encData;
  try {
    encData = await crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      publicKey,
      data
    );
  } catch (e) {
    return showMsg('Encryption failed.', true);
  }
  
  // Download the encrypted data
  const blob = new Blob([encData], { type: 'application/octet-stream' });
  const dlName = file.name + '.rsaenc';
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = dlName;
  a.className = "download-link";
  a.textContent = "Download Encrypted File";
  
  clearMsg();
  showMsg("Encryption successful! Download your file:");
  document.getElementById('output').appendChild(a);
}
    // File Decryption
    async function decryptFile() {
  clearMsg();
  const fileInput = document.getElementById('fileInput');
  const privPem = document.getElementById('privKey').value.trim();
  
  if (!fileInput.files.length) return showMsg('Please select a file to decrypt.', true);
  if (!privPem.includes('PRIVATE KEY')) return showMsg('Please provide a valid private key.', true);
  
  const file = fileInput.files[0];
  const arr = new Uint8Array(await file.arrayBuffer());
  let privateKey;
  
  try {
    privateKey = await importPrivateKey(privPem);
  } catch (e) {
    return showMsg('Failed to parse private key.', true);
  }
  
  // Decrypt the file data with RSA
  let plain;
  try {
    plain = await crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      privateKey,
      arr
    );
  } catch (e) {
    return showMsg('Decryption failed. Wrong private key or corrupted file?', true);
  }
  
  // Download the decrypted data
  const blob = new Blob([plain], { type: 'application/octet-stream' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = file.name.replace(/\.rsaenc$/i, ''); // Remove the extension
  a.className = "download-link";
  a.textContent = "Download Decrypted File";
  
  clearMsg();
  showMsg("Decryption successful! Download your file:");
  document.getElementById('output').appendChild(a);
}
    // UI Helpers
    function showMsg(msg, isError=false) {
      let el = document.getElementById('output');
      el.innerHTML = `<span style="color:${isError?'#f74a7b':'#7a8cf7'}">${msg}</span>`;
    }
    function clearMsg() {
      document.getElementById('output').innerHTML = '';
    }
    // Help Modal
    document.getElementById('helpBtn').onclick = function() {
      document.getElementById('helpModal').classList.add('active');
    };
    function closeHelp() {
      document.getElementById('helpModal').classList.remove('active');
    }
    document.getElementById('helpModal').onclick = function(e) {
      if (e.target === this) closeHelp();
    };
