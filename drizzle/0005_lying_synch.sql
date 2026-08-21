CREATE TABLE `retention_archive_manifests` (
	`id` int AUTO_INCREMENT NOT NULL,
	`retentionPolicyId` int NOT NULL,
	`batchId` varchar(36) NOT NULL,
	`originalThreatId` int NOT NULL,
	`cveId` varchar(64),
	`ghsaId` varchar(64),
	`title` text NOT NULL,
	`severity` enum('Critical','High','Medium','Low') NOT NULL,
	`affectedStack` json NOT NULL,
	`sourceUrl` text NOT NULL,
	`originalIngestionAt` timestamp NOT NULL,
	`archivedAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `retention_archive_manifests_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE INDEX `retention_archive_batch_idx` ON `retention_archive_manifests` (`batchId`);--> statement-breakpoint
CREATE INDEX `retention_archive_archived_idx` ON `retention_archive_manifests` (`archivedAt`);