import { useEffect, useState } from 'react';

export default function WebAuthnTest() {
    const [result, setResult] = useState('');
    const [loading, setLoading] = useState(false);

    useEffect(() => {
        // Initialize any browser-specific APIs after mount
        window.arrayBufferToBase64 = function(buffer) {
            const bytes = new Uint8Array(buffer);
            let binary = '';
            for (let i = 0; i < bytes.byteLength; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return btoa(binary);
        };

        window.uint8ArrayToBase64 = function(uint8Array) {
            return btoa(String.fromCharCode.apply(null, uint8Array));
        };
    }, []);

    async function register() {
        const email = document.getElementById('email').value;
        
        try {
            setLoading(true);
            setResult('Initiating registration...');

            // Generate random challenge
            const challenge = new Uint8Array(32);
            window.crypto.getRandomValues(challenge);

            // Create credentials
            const credential = await navigator.credentials.create({
                publicKey: {
                    challenge: challenge,
                    rp: {
                        name: "NFE Modus Test",
                        id: window.location.hostname || "localhost"
                    },
                    user: {
                        id: Uint8Array.from(email, c => c.charCodeAt(0)),
                        name: email,
                        displayName: email
                    },
                    pubKeyCredParams: [
                        {
                            type: "public-key",
                            alg: -7 // ES256
                        }
                    ],
                    authenticatorSelection: {
                        authenticatorAttachment: "platform",
                        requireResidentKey: false,
                        userVerification: "preferred"
                    },
                    timeout: 60000,
                    attestation: "direct"
                }
            });

            setResult('Credential created, preparing data...');

            // Extract the public key from attestation
            const attestationObject = new Uint8Array(credential.response.attestationObject);
            const authData = attestationObject.slice(37); // Skip CBOR encoding
            const publicKey = authData.slice(55, 87); // Extract public key bytes

            // Create PasskeyCredential JSON
            const credentialData = JSON.stringify({
                id: window.arrayBufferToBase64(credential.rawId),
                publicKey: window.arrayBufferToBase64(publicKey),
                signCount: 0,
                userHandle: window.arrayBufferToBase64(Uint8Array.from(email, c => c.charCodeAt(0))),
                transportsRaw: credential.response.getTransports ? credential.response.getTransports() : []
            });

            // Send to server
            const response = await fetch('/api/auth/register-passkey', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    email: email,
                    credential: {
                        id: window.arrayBufferToBase64(credential.rawId),
                        publicKey: credentialData
                    }
                })
            });

            const result = await response.json();
            if (!result.success) {
                throw new Error(result.message || 'Registration failed');
            }

            setResult(JSON.stringify(result, null, 2));
            setLoading(false);
        } catch (error) {
            console.error('Error:', error);
            setResult('Error: ' + error.message);
            setLoading(false);
        }
    }

    return (
        <div className="container mx-auto p-4">
            <h2 className="text-2xl font-bold mb-4">WebAuthn Registration Test</h2>
            <div className="space-y-4">
                <div className="flex items-center space-x-4">
                    <label htmlFor="email" className="w-20">Email:</label>
                    <input 
                        type="email" 
                        id="email" 
                        defaultValue="info@darkolive.co.uk"
                        className="border p-2 rounded flex-grow" 
                    />
                </div>
                <button 
                    onClick={register}
                    disabled={loading}
                    className="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600 disabled:opacity-50"
                >
                    {loading ? 'Registering...' : 'Register WebAuthn'}
                </button>
                <pre className="bg-gray-100 p-4 rounded mt-4 whitespace-pre-wrap">
                    {result}
                </pre>
            </div>
        </div>
    );
}
