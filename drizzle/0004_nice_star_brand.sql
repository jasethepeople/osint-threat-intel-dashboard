CREATE TABLE `intelligence_retention_policies` (
	`id` int AUTO_INCREMENT NOT NULL,
	`retentionDays` int NOT NULL DEFAULT 90,
	`enabled` boolean NOT NULL DEFAULT false,
	`scheduleCronTaskUid` varchar(65),
	`lastRunAt` timestamp,
	`lastPurgedCount` int NOT NULL DEFAULT 0,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `intelligence_retention_policies_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `saved_triage_views` (
	`id` int AUTO_INCREMENT NOT NULL,
	`name` varchar(120) NOT NULL,
	`stackTerms` json NOT NULL,
	`severities` json NOT NULL,
	`enabled` boolean NOT NULL DEFAULT true,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `saved_triage_views_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
ALTER TABLE `threat_alert_routes` MODIFY COLUMN `channel` enum('owner_in_app','audit_only','slack_webhook','teams_webhook') NOT NULL DEFAULT 'owner_in_app';--> statement-breakpoint
CREATE INDEX `intelligence_retention_policy_schedule_idx` ON `intelligence_retention_policies` (`scheduleCronTaskUid`);--> statement-breakpoint
CREATE INDEX `saved_triage_views_enabled_idx` ON `saved_triage_views` (`enabled`);