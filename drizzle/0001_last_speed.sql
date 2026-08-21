CREATE TABLE `audit_events` (
	`id` int AUTO_INCREMENT NOT NULL,
	`actorKind` enum('system','user','schedule') NOT NULL,
	`actorId` varchar(128),
	`eventType` varchar(100) NOT NULL,
	`entityType` varchar(80) NOT NULL,
	`entityId` varchar(128),
	`payload` json NOT NULL,
	`previousHash` varchar(64),
	`eventHash` varchar(64) NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `audit_events_id` PRIMARY KEY(`id`),
	CONSTRAINT `audit_events_hash_unique` UNIQUE(`eventHash`)
);
--> statement-breakpoint
CREATE TABLE `geo_observations` (
	`id` int AUTO_INCREMENT NOT NULL,
	`threatItemId` int NOT NULL,
	`label` varchar(160) NOT NULL,
	`countryCode` varchar(2),
	`latitude` decimal(9,6),
	`longitude` decimal(9,6),
	`confidence` decimal(3,2) NOT NULL,
	`extractionMethod` varchar(48) NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `geo_observations_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `ingestion_runs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`sourceId` int NOT NULL,
	`requestedBy` enum('system','user','schedule') NOT NULL,
	`status` enum('running','completed','failed','skipped') NOT NULL,
	`itemsFetched` int NOT NULL DEFAULT 0,
	`itemsCreated` int NOT NULL DEFAULT 0,
	`itemsUpdated` int NOT NULL DEFAULT 0,
	`startedAt` timestamp NOT NULL DEFAULT (now()),
	`completedAt` timestamp,
	`errorMessage` text,
	CONSTRAINT `ingestion_runs_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `intelligence_sources` (
	`id` int AUTO_INCREMENT NOT NULL,
	`sourceKey` varchar(80) NOT NULL,
	`name` varchar(160) NOT NULL,
	`kind` enum('nvd','github','rss') NOT NULL,
	`endpoint` text NOT NULL,
	`enabled` boolean NOT NULL DEFAULT true,
	`pollIntervalMinutes` int NOT NULL DEFAULT 30,
	`scheduleCronTaskUid` varchar(65),
	`lastCursor` text,
	`lastSuccessAt` timestamp,
	`lastError` text,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `intelligence_sources_id` PRIMARY KEY(`id`),
	CONSTRAINT `intelligence_sources_key_unique` UNIQUE(`sourceKey`)
);
--> statement-breakpoint
CREATE TABLE `threat_items` (
	`id` int AUTO_INCREMENT NOT NULL,
	`sourceId` int NOT NULL,
	`sourceExternalId` varchar(255) NOT NULL,
	`cveId` varchar(64),
	`ghsaId` varchar(64),
	`title` text NOT NULL,
	`description` text NOT NULL,
	`affectedStack` json NOT NULL,
	`severity` enum('Critical','High','Medium','Low') NOT NULL DEFAULT 'Low',
	`cvssScore` decimal(4,1),
	`sourceUrl` text NOT NULL,
	`sourcePublishedAt` timestamp,
	`sourceUpdatedAt` timestamp,
	`extractedGeoTags` json NOT NULL,
	`zeroDayFlag` boolean NOT NULL DEFAULT false,
	`knownExploitedFlag` boolean NOT NULL DEFAULT false,
	`rawContentHash` varchar(64) NOT NULL,
	`analystBrief` text,
	`analystBriefModel` varchar(80),
	`analystBriefGeneratedAt` timestamp,
	`ingestionTimestamp` timestamp NOT NULL DEFAULT (now()),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `threat_items_id` PRIMARY KEY(`id`),
	CONSTRAINT `threat_items_source_external_unique` UNIQUE(`sourceId`,`sourceExternalId`)
);
--> statement-breakpoint
CREATE INDEX `audit_events_created_idx` ON `audit_events` (`createdAt`);--> statement-breakpoint
CREATE INDEX `geo_observations_threat_idx` ON `geo_observations` (`threatItemId`);--> statement-breakpoint
CREATE INDEX `ingestion_runs_source_started_idx` ON `ingestion_runs` (`sourceId`,`startedAt`);--> statement-breakpoint
CREATE INDEX `intelligence_sources_schedule_idx` ON `intelligence_sources` (`scheduleCronTaskUid`);--> statement-breakpoint
CREATE INDEX `threat_items_severity_ingested_idx` ON `threat_items` (`severity`,`ingestionTimestamp`);--> statement-breakpoint
CREATE INDEX `threat_items_cve_idx` ON `threat_items` (`cveId`);