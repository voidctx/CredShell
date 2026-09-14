(function() {
  if (window.__credshell_hook_installed) return;
  window.__credshell_hook_installed = true;

  if (typeof window.PublicKeyCredential !== 'undefined') {
    PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async function() {
      return true;
    };
    PublicKeyCredential.isConditionalMediationAvailable = async function() {
      return true;
    };
    if (PublicKeyCredential.getClientCapabilities) {
      PublicKeyCredential.getClientCapabilities = async function() {
        return {
          conditionalCreate: true,
          conditionalGet: true,
          hybridTransport: true,
          passkeyPlatformAuthenticator: true,
          userVerificationMgmt: true,
          relatedOrigins: true
        };
      };
    }
  }

  function bufferToBase64url(buffer) {
    if (!buffer) return '';
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  function base64urlToBuffer(base64url) {
    if (!base64url) return new ArrayBuffer(0);
    let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) base64 += '=';
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  function sendToCredShell(action, payload) {
    return new Promise((resolve, reject) => {
      const id = 'credshell_' + Math.random().toString(36).substring(2, 12);

      const handler = (event) => {
        if (event.source !== window || !event.data || event.data.target !== 'credshell-page-hook' || event.data.id !== id) {
          return;
        }
        window.removeEventListener('message', handler);
        if (event.data.success) {
          resolve(event.data.data);
        } else {
          reject(new Error(event.data.error || 'Operation failed in CredShell'));
        }
      };

      window.addEventListener('message', handler);
      window.postMessage({
        target: 'credshell-content-bridge',
        id,
        action,
        payload
      }, '*');

      setTimeout(() => {
        window.removeEventListener('message', handler);
        reject(new Error('CredShell passkey operation timed out'));
      }, 60000);
    });
  }

  const originalCreate = navigator.credentials.create.bind(navigator.credentials);
  const originalGet = navigator.credentials.get.bind(navigator.credentials);

  let inFlightOp = false;

  navigator.credentials.create = async function(options) {
    if (!options || !options.publicKey) {
      return originalCreate(options);
    }

    if (inFlightOp) {
      throw new DOMException('A passkey operation is already in progress', 'AbortError');
    }

    const pk = options.publicKey;
    const rpId = (pk.rp && pk.rp.id) ? pk.rp.id : window.location.hostname;
    const rpName = (pk.rp && pk.rp.name) ? pk.rp.name : rpId;
    const userName = (pk.user && (pk.user.name || pk.user.displayName)) ? (pk.user.name || pk.user.displayName) : 'user';
    const userIdB64 = (pk.user && pk.user.id) ? bufferToBase64url(pk.user.id) : '';
    const challengeB64 = bufferToBase64url(pk.challenge);

    let selectedAlg = -7;
    if (pk.pubKeyCredParams && Array.isArray(pk.pubKeyCredParams)) {
      const algs = pk.pubKeyCredParams.map(p => p.alg);
      if (algs.includes(-7)) {
        selectedAlg = -7;
      } else if (algs.includes(-8)) {
        selectedAlg = -8;
      }
    }

    inFlightOp = true;

    try {
      const data = await sendToCredShell('webauthn_create', {
        rp_id: rpId,
        rp_name: rpName,
        user_name: userName,
        user_id: userIdB64,
        challenge: challengeB64,
        origin: window.location.origin,
        alg: selectedAlg
      });

      const rawIdBuffer = base64urlToBuffer(data.rawId);
      const clientDataBuffer = base64urlToBuffer(data.response.clientDataJSON);
      const attestationBuffer = base64urlToBuffer(data.response.attestationObject);
      const authDataBuffer = data.response.authenticatorData ? base64urlToBuffer(data.response.authenticatorData) : null;
      const spkiBuffer = data.response.publicKey ? base64urlToBuffer(data.response.publicKey) : null;
      const attachment = (pk.authenticatorSelection && pk.authenticatorSelection.authenticatorAttachment)
        ? pk.authenticatorSelection.authenticatorAttachment
        : 'platform';

      return {
        id: data.id,
        rawId: rawIdBuffer,
        type: 'public-key',
        authenticatorAttachment: attachment,
        response: {
          clientDataJSON: clientDataBuffer,
          attestationObject: attestationBuffer,
          getPublicKey: () => spkiBuffer,
          getPublicKeyAlgorithm: () => data.alg || selectedAlg,
          getAuthenticatorData: () => authDataBuffer,
          getTransports: () => ['internal', 'hybrid']
        },
        getClientExtensionResults: () => ({
          credProps: { rk: true }
        })
      };
    } catch (err) {
      if (err.message && (err.message.includes('cancelled') || err.message.includes('declined'))) {
        throw new DOMException('User cancelled the passkey creation', 'NotAllowedError');
      }
      return originalCreate(options);
    } finally {
      inFlightOp = false;
    }
  };

  navigator.credentials.get = async function(options) {
    if (!options || !options.publicKey) {
      return originalGet(options);
    }

    const pk = options.publicKey;
    const rpId = pk.rpId || window.location.hostname;
    const challengeB64 = bufferToBase64url(pk.challenge);

    let allowCreds = [];
    if (pk.allowCredentials && Array.isArray(pk.allowCredentials)) {
      allowCreds = pk.allowCredentials.map(c => bufferToBase64url(c.id));
    }

    if (inFlightOp) {
      throw new DOMException('A passkey operation is already in progress', 'AbortError');
    }

    inFlightOp = true;

    try {
      const data = await sendToCredShell('webauthn_get', {
        rp_id: rpId,
        challenge: challengeB64,
        allow_credentials: allowCreds,
        origin: window.location.origin,
        mediation: options.mediation
      });

      const rawIdBuffer = base64urlToBuffer(data.rawId);
      const clientDataBuffer = base64urlToBuffer(data.response.clientDataJSON);
      const authDataBuffer = base64urlToBuffer(data.response.authenticatorData);
      const signatureBuffer = base64urlToBuffer(data.response.signature);
      const userHandleBuffer = (data.response.userHandle && data.response.userHandle.length > 0)
        ? base64urlToBuffer(data.response.userHandle)
        : null;

      return {
        id: data.id,
        rawId: rawIdBuffer,
        type: 'public-key',
        authenticatorAttachment: 'platform',
        response: {
          clientDataJSON: clientDataBuffer,
          authenticatorData: authDataBuffer,
          signature: signatureBuffer,
          userHandle: userHandleBuffer
        },
        getClientExtensionResults: () => ({})
      };
    } catch (err) {
      if (err.message && (err.message.includes('cancelled') || err.message.includes('declined') || err.message.includes('No passkey found'))) {
        throw new DOMException(err.message, 'NotAllowedError');
      }
      return originalGet(options);
    } finally {
      inFlightOp = false;
    }
  };

  console.log('✓ [CredShell] Passkey Authenticator active on ' + window.location.hostname);
})();
