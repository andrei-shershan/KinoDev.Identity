START TRANSACTION;

CREATE TABLE `RefreshTokens` (
    `Id` int NOT NULL AUTO_INCREMENT,
    `Token` longtext CHARACTER SET utf8mb4 NOT NULL,
    `UserId` longtext CHARACTER SET utf8mb4 NOT NULL,
    `Expires` datetime(6) NOT NULL,
    `Created` datetime(6) NOT NULL,
    CONSTRAINT `PK_RefreshTokens` PRIMARY KEY (`Id`)
) CHARACTER SET=utf8mb4;

INSERT INTO `__EFMigrationsHistory` (`MigrationId`, `ProductVersion`)
VALUES ('20250225201521_Add_RefreshTokens', '8.0.2');

COMMIT;