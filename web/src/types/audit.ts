export interface AuditLogData {
  id: string;
  action: string;
  actorId: string;
  actorType: string;
  resourceId: string;
  resourceType: string;
  operationType: string;
  requestPath: string;
  requestMethod: string;
  requestParams: string;
  responseStatus: number;
  clientIp: string;
  auditTimestamp: Date;
  sessionId: string;
  userAgent: string;
  success: boolean;
  sensitiveOperation: boolean;
  complianceFlags: string[];
  details: string;
}

// Type used by Dgraph client and application code
export interface AuditLogInput {
  action: string;
  actorId: string;
  actorType: string;
  resourceId?: string;
  resourceType?: string;
  operationType: string;
  requestPath?: string;
  requestMethod?: string;
  requestParams?: string;
  responseStatus?: number;
  clientIp: string;
  sessionId?: string;
  userAgent: string;
  success: boolean;
  sensitiveOperation?: boolean;
  complianceFlags?: string[];
  details?: string;
  timestamp?: Date;
}
