let encryptionKey = null;
let currentKeyId = null;
let sealed = true;

export const getEncryptionKey = () => encryptionKey;
export const setEncryptionKey = (key) => { encryptionKey = key; };

export const getCurrentKeyId = () => currentKeyId;
export const setCurrentKeyId = (id) => { currentKeyId = id; };

export const isSealed = () => sealed;
export const setSealed = (state) => { sealed = state; };
