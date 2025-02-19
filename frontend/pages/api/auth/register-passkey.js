export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const { email, credential } = req.body;

        // Format credential data as PasskeyCredential
        const credentialData = {
            id: credential.id,
            publicKey: credential.publicKey,
            signCount: 0,
            userHandle: btoa(email), // base64 encode email as user handle
            transportsRaw: []
        };

        // Base64 encode the credential data for transmission
        const base64CredentialData = btoa(JSON.stringify(credentialData));

        // Call the GraphQL endpoint
        const response = await fetch('http://localhost:8686/graphql', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                query: `query RegisterWebAuthn($req: WebAuthnRegistrationRequestInput!) {
                    registerWebAuthn(req: $req) {
                        success
                        message
                        userDID
                    }
                }`,
                variables: {
                    req: {
                        email: email,
                        credentialData: base64CredentialData, // Send base64 encoded credential data
                        deviceID: credential.id
                    }
                }
            })
        });

        const result = await response.json();
        
        if (result.errors) {
            console.error('GraphQL Errors:', result.errors);
            return res.status(400).json(result);
        }
        
        return res.status(200).json(result.data.registerWebAuthn);
    } catch (error) {
        console.error('Error in register-passkey:', error);
        return res.status(500).json({ error: error.message });
    }
}
