-- TOTP MFA secrets

CREATE TABLE iam_totp_mfa (ID BIGINT AUTO_INCREMENT NOT NULL, active TINYINT(1) default 0 NOT NULL, secret VARCHAR(256), ACCOUNT_ID BIGINT, PRIMARY KEY (ID));

CREATE TABLE iam_totp_recovery_code (ID BIGINT AUTO_INCREMENT NOT NULL, code VARCHAR(255) NOT NULL, totp_mfa_id BIGINT NOT NULL, PRIMARY KEY (ID));

ALTER TABLE iam_account ADD totp_mfa_id BIGINT;

ALTER TABLE iam_account ADD CONSTRAINT FK_iam_account_totp_mfa_id FOREIGN KEY (totp_mfa_id) REFERENCES iam_totp_mfa (ID);

ALTER TABLE iam_totp_mfa ADD CONSTRAINT FK_iam_totp_mfa_account_id FOREIGN KEY (ACCOUNT_ID) REFERENCES iam_account (ID);

ALTER TABLE iam_totp_recovery_code ADD CONSTRAINT FK_iam_totp_recovery_code_totp_mfa_id FOREIGN KEY (totp_mfa_id) REFERENCES iam_totp_mfa (ID);

CREATE INDEX idx_iam_totp_mfa_id ON iam_account (totp_mfa_id);