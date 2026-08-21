CREATE TABLE `threat_alert_routes` (
	`id` int AUTO_INCREMENT NOT NULL,
	`name` varchar(120) NOT NULL,
	`watchlistId` int,
	`minSeverity` enum('Critical','High','Medium','Low') NOT NULL DEFAULT 'Critical',
	`includeZeroDays` boolean NOT NULL DEFAULT true,
	`includeKnownExploited` boolean NOT NULL DEFAULT false,
	`channel` enum('owner_in_app') NOT NULL DEFAULT 'owner_in_app',
	`enabled` boolean NOT NULL DEFAULT true,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `threat_alert_routes_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `threat_watchlists` (
	`id` int AUTO_INCREMENT NOT NULL,
	`name` varchar(120) NOT NULL,
	`stackTerms` json NOT NULL,
	`enabled` boolean NOT NULL DEFAULT true,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `threat_watchlists_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE INDEX `threat_alert_routes_enabled_idx` ON `threat_alert_routes` (`enabled`);--> statement-breakpoint
CREATE INDEX `threat_alert_routes_watchlist_idx` ON `threat_alert_routes` (`watchlistId`);--> statement-breakpoint
CREATE INDEX `threat_watchlists_enabled_idx` ON `threat_watchlists` (`enabled`);