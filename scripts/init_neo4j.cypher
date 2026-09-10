// Neo4j Schema Initialization Script — SIH Problem Statement 26106
// Role 4: Graph & Campaign Correlation Module

// --- 1. UNIQUENESS CONSTRAINTS ---

// Ensure Email nodes are identified uniquely by their email_id
CREATE CONSTRAINT email_id_unique IF NOT EXISTS
FOR (e:Email) REQUIRE e.email_id IS UNIQUE;

// Ensure Domain nodes are identified uniquely by normalized domain name
CREATE CONSTRAINT domain_name_unique IF NOT EXISTS
FOR (d:Domain) REQUIRE d.name IS UNIQUE;

// Ensure IP nodes are identified uniquely by canonical IP address
CREATE CONSTRAINT ip_address_unique IF NOT EXISTS
FOR (i:IP) REQUIRE i.address IS UNIQUE;

// Ensure URL nodes are identified uniquely by SHA-256 hash of normalized URL
CREATE CONSTRAINT url_hash_unique IF NOT EXISTS
FOR (u:URL) REQUIRE u.url_hash IS UNIQUE;

// Ensure Hash nodes are identified uniquely by lowercase cryptographic hash value
CREATE CONSTRAINT hash_value_unique IF NOT EXISTS
FOR (h:Hash) REQUIRE h.value IS UNIQUE;

// Ensure Campaign nodes are identified uniquely by campaign_id
CREATE CONSTRAINT campaign_id_unique IF NOT EXISTS
FOR (c:Campaign) REQUIRE c.campaign_id IS UNIQUE;

// Ensure ASN nodes are identified uniquely by ASN number
CREATE CONSTRAINT asn_number_unique IF NOT EXISTS
FOR (a:ASN) REQUIRE a.number IS UNIQUE;

// --- 2. PERFORMANCE INDEXES ---

// Index timestamps for rapid temporal querying and windowed correlation
CREATE INDEX email_timestamp_idx IF NOT EXISTS
FOR (e:Email) ON (e.timestamp);

// Index risk scores for rapid prioritization
CREATE INDEX email_risk_score_idx IF NOT EXISTS
FOR (e:Email) ON (e.risk_score);

CREATE INDEX domain_risk_score_idx IF NOT EXISTS
FOR (d:Domain) ON (d.risk_score);

CREATE INDEX ip_risk_score_idx IF NOT EXISTS
FOR (i:IP) ON (i.risk_score);

CREATE INDEX campaign_confidence_idx IF NOT EXISTS
FOR (c:Campaign) ON (c.confidence);
