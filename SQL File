-- =====================================================
-- PROJECT: BANKING TRANSACTION FRAUD & RISK ANALYSIS
-- TOOL: MySQL
-- DATASET: banking_transactions.csv
-- =====================================================

-- SECTION 1: DATABASE SELECTION
USE banking_fraud_analysis;

SELECT DATABASE() AS current_database;

-- SECTION 2: TABLE VALIDATION
SHOW TABLES;

-- SECTION 3: RECORD COUNT VALIDATION
SELECT COUNT(*) AS total_records
-- SECTION 4: TABLE STRUCTURE VALIDATION
-- Check all column names and data types

DESCRIBE banking_transactions;
-- SECTION 5: DATA QUALITY CHECK
-- Check missing values in important columns
SELECT
    COUNT(*) AS total_records,
    SUM(transaction_id IS NULL) AS missing_transaction_id,
    SUM(transaction_amount IS NULL) AS missing_transaction_amount,
    SUM(fraud_flag IS NULL) AS missing_fraud_flag
FROM banking_transactions;
-- SECTION 6: DUPLICATE ID CHECK
-- Check whether transaction IDs are duplicated
SELECT
    transaction_id,
    COUNT(*) AS id_count
FROM banking_transactions
GROUP BY transaction_id
HAVING COUNT(*) > 1;
-- SECTION 7: FRAUD DISTRIBUTION ANALYSIS
-- Count fraud and non-fraud transactions
SELECT
    fraud_flag,
    COUNT(*) AS total_transactions
FROM banking_transactions
GROUP BY fraud_flag;
-- SECTION 8: FRAUD RATE ANALYSIS
-- Calculate fraud and non-fraud percentage
SELECT
    fraud_flag,
    COUNT(*) AS total_transactions,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM banking_transactions), 2) AS percentage
FROM banking_transactions
GROUP BY fraud_flag;
-- SECTION 9: TRANSACTION AMOUNT ANALYSIS
-- Compare transaction amounts for fraud and non-fraud
SELECT
    fraud_flag,
    COUNT(*) AS total_transactions,
    ROUND(AVG(transaction_amount), 2) AS avg_transaction_amount,
    ROUND(MIN(transaction_amount), 2) AS min_transaction_amount,
    ROUND(MAX(transaction_amount), 2) AS max_transaction_amount,
    ROUND(SUM(transaction_amount), 2) AS total_transaction_amount
FROM banking_transactions
GROUP BY fraud_flag;
-- SECTION 10: PAYMENT CHANNEL FRAUD ANALYSIS
-- Compare fraud rates across payment channels
SELECT
    payment_channel,
    COUNT(*) AS total_transactions,
    SUM(CASE WHEN fraud_flag = TRUE THEN 1 ELSE 0 END) AS fraud_transactions,
    ROUND(
        SUM(CASE WHEN fraud_flag = TRUE THEN 1 ELSE 0 END)
        * 100.0 / COUNT(*),
        2
    ) AS fraud_rate_percentage
FROM banking_transactions
GROUP BY payment_channel
ORDER BY fraud_rate_percentage DESC;
-- SECTION 10B: PAYMENT CHANNEL FRAUD ANALYSIS FIX
SELECT
    payment_channel,
    COUNT(*) AS total_transactions,
    SUM(
        CASE
            WHEN CAST(fraud_flag AS CHAR) = 'TRUE' THEN 1
            ELSE 0
        END
    ) AS fraud_transactions,
    ROUND(
        SUM(
            CASE
                WHEN CAST(fraud_flag AS CHAR) = 'TRUE' THEN 1
                ELSE 0
            END
        ) * 100.0 / COUNT(*),
        2
    ) AS fraud_rate_percentage
FROM banking_transactions
GROUP BY payment_channel
ORDER BY fraud_rate_percentage DESC;
-- SECTION 11: AUTHENTICATION TYPE FRAUD ANALYSIS
SELECT
    authentication_type,
    COUNT(*) AS total_transactions,
    SUM(
        CASE
            WHEN CAST(fraud_flag AS CHAR) = 'TRUE' THEN 1
            ELSE 0
        END
    ) AS fraud_transactions,
    ROUND(
        SUM(
            CASE
                WHEN CAST(fraud_flag AS CHAR) = 'TRUE' THEN 1
                ELSE 0
            END
        ) * 100.0 / COUNT(*),
        2
    ) AS fraud_rate_percentage
FROM banking_transactions
GROUP BY authentication_type
ORDER BY fraud_rate_percentage DESC;
-- SECTION 12: SUSPICIOUS IP FRAUD ANALYSIS
SELECT
    suspicious_ip_flag,
    COUNT(*) AS total_transactions,
    SUM(
        CASE
            WHEN CAST(fraud_flag AS CHAR) = 'TRUE' THEN 1
            ELSE 0
        END
    ) AS fraud_transactions,
    ROUND(
        SUM(
            CASE
                WHEN CAST(fraud_flag AS CHAR) = 'TRUE' THEN 1
                ELSE 0
            END
        ) * 100.0 / COUNT(*),
        2
    ) AS fraud_rate_percentage
FROM banking_transactions
GROUP BY suspicious_ip_flag
ORDER BY fraud_rate_percentage DESC;
-- SECTION 13: HOURLY FRAUD ANALYSIS
SELECT
    transaction_time_hour,
    COUNT(*) AS total_transactions,
    SUM(
        CASE
            WHEN CAST(fraud_flag AS CHAR) = 'TRUE' THEN 1
            ELSE 0
        END
    ) AS fraud_transactions,
    ROUND(
        SUM(
            CASE
                WHEN CAST(fraud_flag AS CHAR) = 'TRUE' THEN 1
                ELSE 0
            END
        ) * 100.0 / COUNT(*),
        2
    ) AS fraud_rate_percentage
FROM banking_transactions
GROUP BY transaction_time_hour
ORDER BY fraud_rate_percentage DESC;
-- SECTION 14: DEVICE RISK SCORE ANALYSIS
SELECT
    fraud_flag,
    COUNT(*) AS total_transactions,
    ROUND(AVG(device_risk_score), 2) AS avg_device_risk_score,
    ROUND(AVG(anomaly_score), 2) AS avg_anomaly_score
FROM banking_transactions
GROUP BY fraud_flag;
-- SECTION 15: FAILED TRANSACTIONS ANALYSIS

SELECT
    fraud_flag,
    COUNT(*) AS total_transactions,
    ROUND(AVG(failed_transactions_last_30d), 2) AS avg_failed_transactions
FROM banking_transactions
GROUP BY fraud_flag;
-- SECTION 16: TRANSACTION FREQUENCY ANALYSIS
SELECT
    fraud_flag,
    COUNT(*) AS total_transactions,
    ROUND(AVG(transfer_frequency), 2) AS avg_transfer_frequency,
    ROUND(AVG(daily_transaction_count), 2) AS avg_daily_transaction_count,
    ROUND(AVG(transaction_velocity_score), 2) AS avg_transaction_velocity
FROM banking_transactions
GROUP BY fraud_flag;
-- SECTION 17: ACCOUNT AGE ANALYSIS
SELECT
    fraud_flag,
    COUNT(*) AS total_transactions,
    ROUND(AVG(account_age_days), 2) AS avg_account_age_days
FROM banking_transactions
GROUP BY fraud_flag;
-- SECTION 18: INTERNATIONAL TRANSACTION ANALYSIS
SELECT
    international_transaction_flag,
    COUNT(*) AS total_transactions,
    SUM(
        CASE
            WHEN CAST(fraud_flag AS CHAR) = 'TRUE' THEN 1
            ELSE 0
        END
    ) AS fraud_transactions,
    ROUND(
        SUM(
            CASE
                WHEN CAST(fraud_flag AS CHAR) = 'TRUE' THEN 1
                ELSE 0
            END
        ) * 100.0 / COUNT(*),
        2
    ) AS fraud_rate_percentage
FROM banking_transactions
GROUP BY international_transaction_flag
ORDER BY fraud_rate_percentage DESC;
-- SECTION 19: TRANSACTION AMOUNT ANALYSIS
SELECT
    fraud_flag,
    COUNT(*) AS total_transactions,
    ROUND(AVG(transaction_amount), 2) AS avg_transaction_amount,
    ROUND(MIN(transaction_amount), 2) AS min_transaction_amount,
    ROUND(MAX(transaction_amount), 2) AS max_transaction_amount,
    ROUND(SUM(transaction_amount), 2) AS total_transaction_amount
FROM banking_transactions
GROUP BY fraud_flag;
-- SECTION 20: ACCOUNT AGE ANALYSIS
SELECT
    fraud_flag,
    COUNT(*) AS total_transactions,
    ROUND(AVG(account_age_days), 2) AS avg_account_age_days,
    ROUND(AVG(transaction_amount), 2) AS avg_transaction_amount
FROM banking_transactions
GROUP BY fraud_flag;
-- SECTION 22: DATA QUALITY CHECK
SELECT
    COUNT(*) AS total_records,
    SUM(CASE WHEN transaction_id IS NULL THEN 1 ELSE 0 END) AS null_transaction_ids,
    COUNT(DISTINCT transaction_id) AS unique_transaction_ids
FROM banking_transactions;
-- SECTION 23: MISSING VALUES CHECK
SELECT
    SUM(CASE WHEN transaction_amount IS NULL THEN 1 ELSE 0 END) AS null_transaction_amount,
    SUM(CASE WHEN fraud_flag IS NULL THEN 1 ELSE 0 END) AS null_fraud_flag,
    SUM(CASE WHEN payment_channel IS NULL THEN 1 ELSE 0 END) AS null_payment_channel,
    SUM(CASE WHEN authentication_type IS NULL THEN 1 ELSE 0 END) AS null_authentication_type
FROM banking_transactions;
-- SECTION 24: OVERALL FRAUD KPIs
SELECT
    COUNT(*) AS total_transactions,
    SUM(CASE WHEN fraud_flag = TRUE THEN 1 ELSE 0 END) AS fraud_transactions,
    ROUND(
        SUM(CASE WHEN fraud_flag = TRUE THEN 1 ELSE 0 END)
        * 100.0 / COUNT(*), 2
    ) AS fraud_rate_percentage,
    ROUND(AVG(transaction_amount), 2) AS avg_transaction_amount,
    ROUND(SUM(transaction_amount), 2) AS total_transaction_amount
FROM banking_transactions;
-- SECTION 24A: CORRECTED OVERALL FRAUD KPIs
SELECT
    COUNT(*) AS total_transactions,
    SUM(
        CASE
            WHEN CAST(fraud_flag AS CHAR) = 'TRUE' THEN 1
            ELSE 0
        END
    ) AS fraud_transactions,
    ROUND(
        SUM(
            CASE
                WHEN CAST(fraud_flag AS CHAR) = 'TRUE' THEN 1
                ELSE 0
            END
        ) * 100.0 / COUNT(*),
        2
    ) AS fraud_rate_percentage,
    ROUND(AVG(transaction_amount), 2) AS avg_transaction_amount,
    ROUND(SUM(transaction_amount), 2) AS total_transaction_amount
FROM banking_transactions;
-- SECTION 25: FRAUD SUMMARY BY PAYMENT CHANNEL
SELECT
    payment_channel,
    COUNT(*) AS total_transactions,
    SUM(
        CASE
            WHEN CAST(fraud_flag AS CHAR) = 'TRUE' THEN 1
            ELSE 0
        END
    ) AS fraud_transactions,
    ROUND(
        SUM(
            CASE
                WHEN CAST(fraud_flag AS CHAR) = 'TRUE' THEN 1
                ELSE 0
            END
        ) * 100.0 / COUNT(*),
        2
    ) AS fraud_rate_percentage,
    ROUND(AVG(transaction_amount), 2) AS avg_transaction_amount
FROM banking_transactions
GROUP BY payment_channel
ORDER BY fraud_rate_percentage DESC;
-- SECTION 26: FRAUD SUMMARY BY AUTHENTICATION TYPE
SELECT
    authentication_type,
    COUNT(*) AS total_transactions,
    SUM(
        CASE
            WHEN CAST(fraud_flag AS CHAR) = 'TRUE' THEN 1
            ELSE 0
        END
    ) AS fraud_transactions,
    ROUND(
        SUM(
            CASE
                WHEN CAST(fraud_flag AS CHAR) = 'TRUE' THEN 1
                ELSE 0
            END
        ) * 100.0 / COUNT(*),
        2
    ) AS fraud_rate_percentage
FROM banking_transactions
GROUP BY authentication_type
ORDER BY fraud_rate_percentage DESC; 
-- SECTION 27: SUSPICIOUS IP FRAUD ANALYSIS
SELECT
    suspicious_ip_flag,
    COUNT(*) AS total_transactions,
    SUM(
        CASE
            WHEN CAST(fraud_flag AS CHAR) = 'TRUE' THEN 1
            ELSE 0
        END
    ) AS fraud_transactions,
    ROUND(
        SUM(
            CASE
                WHEN CAST(fraud_flag AS CHAR) = 'TRUE' THEN 1
                ELSE 0
            END
        ) * 100.0 / COUNT(*),
        2
    ) AS fraud_rate_percentage
FROM banking_transactions
GROUP BY suspicious_ip_flag
ORDER BY fraud_rate_percentage DESC;
-- SECTION 28: DEVICE RISK SCORE ANALYSI
SELECT
    CASE
        WHEN device_risk_score < 25 THEN 'Low Risk'
        WHEN device_risk_score < 50 THEN 'Medium Risk'
        WHEN device_risk_score < 75 THEN 'High Risk'
        ELSE 'Very High Risk'
    END AS device_risk_category,
    COUNT(*) AS total_transactions,
    SUM(
        CASE
            WHEN CAST(fraud_flag AS CHAR) = 'TRUE' THEN 1
            ELSE 0
        END
    ) AS fraud_transactions,
    ROUND(
        SUM(
            CASE
                WHEN CAST(fraud_flag AS CHAR) = 'TRUE' THEN 1
                ELSE 0
            END
        ) * 100.0 / COUNT(*),
        2
    ) AS fraud_rate_percentage
FROM banking_transactions
GROUP BY device_risk_category
ORDER BY fraud_rate_percentage DESC;
-- SECTION 29: TRANSACTION AMOUNT ANALYSIS
SELECT
    CASE
        WHEN transaction_amount < 5000 THEN 'Low Amount'
        WHEN transaction_amount < 15000 THEN 'Medium Amount'
        WHEN transaction_amount < 25000 THEN 'High Amount'
        ELSE 'Very High Amount'
    END AS amount_category,
    COUNT(*) AS total_transactions,
    SUM(
        CASE
            WHEN CAST(fraud_flag AS CHAR) = 'TRUE' THEN 1
            ELSE 0
        END
    ) AS fraud_transactions,
    ROUND(
        SUM(
            CASE
                WHEN CAST(fraud_flag AS CHAR) = 'TRUE' THEN 1
                ELSE 0
            END
        ) * 100.0 / COUNT(*),
        2
    ) AS fraud_rate_percentage
FROM banking_transactions
GROUP BY amount_category
ORDER BY fraud_rate_percentage DESC;
-- SECTION 30: LOGIN ATTEMPTS ANALYSIS
SELECT
    login_attempts,
    COUNT(*) AS total_transactions,
    SUM(
        CASE
            WHEN CAST(fraud_flag AS CHAR) = 'TRUE' THEN 1
            ELSE 0
        END
    ) AS fraud_transactions,
    ROUND(
        SUM(
            CASE
                WHEN CAST(fraud_flag AS CHAR) = 'TRUE' THEN 1
                ELSE 0
            END
        ) * 100.0 / COUNT(*),
        2
    ) AS fraud_rate_percentage
FROM banking_transactions
GROUP BY login_attempts
ORDER BY fraud_rate_percentage DESC;
-- SECTION 31: FAILED TRANSACTIONS ANALYSIS
SELECT
    failed_transactions_last_30d,
    COUNT(*) AS total_transactions,
    SUM(
        CASE
            WHEN CAST(fraud_flag AS CHAR) = 'TRUE' THEN 1
            ELSE 0
        END
    ) AS fraud_transactions,
    ROUND(
        SUM(
            CASE
                WHEN CAST(fraud_flag AS CHAR) = 'TRUE' THEN 1
                ELSE 0
            END
        ) * 100.0 / COUNT(*),
        2
    ) AS fraud_rate_percentage
FROM banking_transactions
GROUP BY failed_transactions_last_30d
ORDER BY fraud_rate_percentage DESC;
-- SECTION 32: SESSION DURATION ANALYSIS
SELECT
    CASE
        WHEN session_duration_minutes < 5 THEN 'Short Session'
        WHEN session_duration_minutes < 15 THEN 'Medium Session'
        ELSE 'Long Session'
    END AS session_category,
    COUNT(*) AS total_transactions,
    SUM(
        CASE
            WHEN CAST(fraud_flag AS CHAR) = 'TRUE' THEN 1
            ELSE 0
        END
    ) AS fraud_transactions,
    ROUND(
        SUM(
            CASE
                WHEN CAST(fraud_flag AS CHAR) = 'TRUE' THEN 1
                ELSE 0
            END
        ) * 100.0 / COUNT(*),
        2
    ) AS fraud_rate_percentage
FROM banking_transactions
GROUP BY session_category
ORDER BY fraud_rate_percentage DESC;
-- SECTION 33: TRANSACTION VELOCITY ANALYSIS
SELECT
    CASE
        WHEN transaction_velocity_score < 25 THEN 'Low Velocity'
        WHEN transaction_velocity_score < 50 THEN 'Medium Velocity'
        WHEN transaction_velocity_score < 75 THEN 'High Velocity'
        ELSE 'Very High Velocity'
    END AS velocity_category,
    COUNT(*) AS total_transactions,
    SUM(
        CASE
            WHEN CAST(fraud_flag AS CHAR) = 'TRUE' THEN 1
            ELSE 0
        END
    ) AS fraud_transactions,
    ROUND(
        SUM(
            CASE
                WHEN CAST(fraud_flag AS CHAR) = 'TRUE' THEN 1
                ELSE 0
            END
        ) * 100.0 / COUNT(*),
        2
    ) AS fraud_rate_percentage
FROM banking_transactions
GROUP BY velocity_category
ORDER BY fraud_rate_percentage DESC;
-- SECTION 34: OVERALL PROJECT SUMMARY
SELECT
    COUNT(*) AS total_transactions,
    SUM(
        CASE
            WHEN CAST(fraud_flag AS CHAR) = 'TRUE'
            THEN 1 ELSE 0
        END
    ) AS fraud_transactions,
    SUM(
        CASE
            WHEN CAST(fraud_flag AS CHAR) = 'FALSE'
            THEN 1 ELSE 0
        END
    ) AS legitimate_transactions,
    ROUND(
        SUM(
            CASE
                WHEN CAST(fraud_flag AS CHAR) = 'TRUE'
                THEN 1 ELSE 0
            END
        ) * 100.0 / COUNT(*),
        2
    ) AS fraud_rate_percentage,
    ROUND(AVG(transaction_amount), 2)
        AS avg_transaction_amount,
    ROUND(SUM(transaction_amount), 2)
        AS total_transaction_amount
FROM banking_transactions;
