// Audit log input interface
export interface AuditLogInput {
  action: string;
  userId?: string;
  resourceId?: string;
  resourceType?: string;
  details?: Record<string, unknown>;
  ipAddress?: string;
  userAgent?: string;
  success?: boolean;
  metadata?: Record<string, unknown>; // Added metadata field
}
