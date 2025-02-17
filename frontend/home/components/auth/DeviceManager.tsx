import React, { useState, useEffect } from 'react';
import { authClient, DeviceCredential } from '../../auth/api-client';
import { useAuth } from '../../auth/useAuth';

export function DeviceManager() {
    const { user } = useAuth();
    const [devices, setDevices] = useState<DeviceCredential[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState<Error | null>(null);

    useEffect(() => {
        if (user?.email) {
            loadDevices();
        }
    }, [user]);

    const loadDevices = async () => {
        try {
            setIsLoading(true);
            // Fetch devices from the API
            const response = await fetch(`/api/auth/devices?email=${encodeURIComponent(user!.email)}`);
            const data = await response.json();
            setDevices(data);
        } catch (err) {
            setError(err as Error);
        } finally {
            setIsLoading(false);
        }
    };

    const handleRevokeDevice = async (did: string) => {
        try {
            await authClient.revokeDevice(user!.email, did);
            // Refresh device list
            loadDevices();
        } catch (err) {
            setError(err as Error);
        }
    };

    if (isLoading) {
        return (
            <div className="flex justify-center items-center p-4">
                <svg className="animate-spin h-5 w-5 text-gray-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
            </div>
        );
    }

    if (error) {
        return (
            <div className="text-red-600 p-4">
                Error loading devices: {error.message}
            </div>
        );
    }

    return (
        <div className="bg-white shadow rounded-lg p-6">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Registered Devices</h3>
            
            <div className="space-y-4">
                {devices.map((device) => (
                    <div key={device.did} className="flex items-center justify-between p-4 border rounded-lg">
                        <div>
                            <div className="font-medium">
                                Device ID: {device.deviceId.substring(0, 8)}...
                            </div>
                            <div className="text-sm text-gray-500">
                                Last synced: {new Date(device.lastSyncTime).toLocaleDateString()}
                            </div>
                            <div className="text-sm">
                                {device.isVerified ? (
                                    <span className="text-green-600">✓ Verified</span>
                                ) : (
                                    <span className="text-yellow-600">Pending verification</span>
                                )}
                            </div>
                        </div>
                        
                        <button
                            onClick={() => handleRevokeDevice(device.did)}
                            className="ml-4 px-3 py-1 text-sm text-red-600 hover:text-red-800 focus:outline-none"
                        >
                            Revoke
                        </button>
                    </div>
                ))}

                {devices.length === 0 && (
                    <div className="text-gray-500 text-center py-4">
                        No devices registered
                    </div>
                )}
            </div>
        </div>
    );
}
