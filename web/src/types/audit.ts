export interface AuditLogData {
  id: string;
  userId: string;
  action: string;
  details: string;
  ipAddress: string;
  userAgent: string;
  metadata: Record<string, unknown>;
  timestamp: Date;
}

// Type used by Dgraph client and application code
export interface AuditLogInput {
  userId: string;
  action: string;
  details: string;
  ipAddress: string;
  userAgent: string;
  metadata: Record<string, unknown>;
  timestamp?: Date;
}
