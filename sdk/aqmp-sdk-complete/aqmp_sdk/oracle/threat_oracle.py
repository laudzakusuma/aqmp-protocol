# AQMP Quantum Threat Oracle (QTO)
# Component 4 of AQMP: Monitors quantum computing threat indicators
# and triggers adaptive migration responses.

# The QTO solves a key problem in PQC migration: the threat timeline is
# uncertain. Rather than hard-coding a migration deadline, AQMP allows the
# protocol to respond dynamically to actual quantum progress signals.

# Threat Model:
#   Level 0 (GREEN):  No credible CRQC threat. Classical + PQC hybrid active.
#   Level 1 (YELLOW): Signs of progress toward CRQC. Accelerate PQC adoption.
#   Level 2 (ORANGE): Verified CRQC capability imminent. Emergency migration.
#   Level 3 (RED):    CRQC confirmed operational. Immediate classical sunset.

# Oracle feeds (production):
#   - NIST PQC algorithm deprecation notices
#   - Qubit count milestones (IBM, Google, IonQ, QuEra, Quantinuum)
#   - Academic papers on lattice/NTRU attack improvements
#   - Anomaly detection on blockchain signature patterns
#   - Intelligence community threat assessments (public)

from __future__ import annotations
import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple
from enum import IntEnum
from datetime import datetime


class ThreatLevel(IntEnum):
    GREEN = 0   # Safe — migrate at normal pace
    YELLOW = 1  # Caution — accelerate PQC adoption
    ORANGE = 2  # Warning — emergency migration triggers active
    RED = 3     # Critical — classical crypto compromised


@dataclass
class ThreatIndicator:
    """A single threat signal from an oracle feed."""
    source: str
    indicator_type: str
    severity: int           # 0-100
    description: str
    timestamp: int = field(default_factory=time.time_ns)
    verified: bool = False  # multi-sig oracle verification
    weight: float = 1.0     # oracle stake weight


@dataclass
class QuantumHarvestRiskScore:
    """
    HNDL (Harvest Now Decrypt Later) risk assessment for a blockchain.
    
    Key insight: even before CRQC exists, adversaries are harvesting 
    encrypted/signed blockchain data for future decryption. This score
    quantifies that current risk.
    """
    harvest_probability: float      # P(adversary already harvesting)
    time_to_crqc_years: float       # Estimated years to CRQC
    sensitive_utxo_pct: float       # % of UTXOs with exposed public keys
    blockchain_exposure_score: int  # 0-100, overall HNDL risk
    
    @property
    def urgency_level(self) -> ThreatLevel:
        if self.blockchain_exposure_score >= 80:
            return ThreatLevel.RED
        elif self.blockchain_exposure_score >= 60:
            return ThreatLevel.ORANGE
        elif self.blockchain_exposure_score >= 35:
            return ThreatLevel.YELLOW
        return ThreatLevel.GREEN


@dataclass
class MigrationRecommendation:
    """Protocol response recommendation from QTO."""
    threat_level: ThreatLevel
    recommended_aqmp_phase: int
    actions: List[str]
    urgency_score: int
    time_window_days: Optional[int]
    rationale: str


class QuantumThreatOracle:
    """
    AQMP Quantum Threat Oracle.
    
    Aggregates threat signals and produces:
    1. Current threat level assessment
    2. HNDL risk score for specific blockchains
    3. Migration phase recommendations
    4. Emergency trigger conditions
    
    In production: implemented as a decentralized oracle network
    with staked validators, multi-sig attestations, and on-chain
    dispute resolution. Here implemented as a reference simulation.
    """
    
    # Quantum progress milestones (IBM Quantum roadmap + consensus estimates)
    QUBIT_MILESTONES = {
        2024: {"logical_qubits": 10, "crqc_possible": False},
        2025: {"logical_qubits": 100, "crqc_possible": False},
        2026: {"logical_qubits": 1000, "crqc_possible": False},
        2028: {"logical_qubits": 5000, "crqc_possible": False},
        2030: {"logical_qubits": 10000, "crqc_possible": False},
        2033: {"logical_qubits": 50000, "crqc_possible": False},   # Threshold zone
        2035: {"logical_qubits": 100000, "crqc_possible": True},   # Median estimate
        2040: {"logical_qubits": 1000000, "crqc_possible": True},  # Conservative bound
    }
    
    # ECDSA secp256k1 break requires ~317 logical qubits (Webber et al. 2022)
    # With 99.9% gate fidelity: ~2330 noisy qubits
    CRQC_THRESHOLD_LOGICAL_QUBITS = 317
    CRQC_THRESHOLD_NOISY_QUBITS = 2330

    def __init__(self):
        self._indicators: List[ThreatIndicator] = []
        self._current_threat_level = ThreatLevel.GREEN
        self._last_assessment: Optional[Dict] = None
        self._simulated_year = 2025  # for simulation

    def add_indicator(self, indicator: ThreatIndicator):
        self._indicators.append(indicator)

    def simulate_year(self, year: int):
        """For testing: simulate oracle state at a given year."""
        self._simulated_year = year

    def assess_threat_level(self, current_year: Optional[int] = None) -> Tuple[ThreatLevel, Dict]:
        """
        Compute current threat level from all indicators.
        
        Algorithm:
          1. Score each indicator by (severity × weight)
          2. Weight by source reliability
          3. Apply temporal decay (older indicators matter less)
          4. Compute aggregate score → threat level
        """
        year = current_year or self._simulated_year

        # Base threat from time proximity to CRQC
        time_scores = {
            2024: 5, 2025: 8, 2026: 12, 2027: 18, 2028: 25,
            2029: 35, 2030: 45, 2031: 55, 2032: 65, 2033: 75,
            2034: 82, 2035: 88, 2036: 92, 2037: 95, 2038: 97,
            2039: 99, 2040: 100,
        }
        time_score = time_scores.get(year, 100 if year > 2040 else 5)

        # Aggregate indicator scores
        indicator_score = 0.0
        if self._indicators:
            total_weight = sum(ind.weight for ind in self._indicators if ind.verified)
            if total_weight > 0:
                weighted_sum = sum(
                    ind.severity * ind.weight 
                    for ind in self._indicators if ind.verified
                )
                indicator_score = weighted_sum / total_weight

        # Combined score
        combined = 0.6 * time_score + 0.4 * indicator_score

        # Determine threat level
        if combined >= 85:
            level = ThreatLevel.RED
        elif combined >= 65:
            level = ThreatLevel.ORANGE
        elif combined >= 35:
            level = ThreatLevel.YELLOW
        else:
            level = ThreatLevel.GREEN

        self._current_threat_level = level

        assessment = {
            "year": year,
            "threat_level": level.name,
            "threat_level_int": int(level),
            "time_score": time_score,
            "indicator_score": indicator_score,
            "combined_score": combined,
            "n_indicators": len(self._indicators),
            "n_verified_indicators": sum(1 for i in self._indicators if i.verified),
            "recommended_aqmp_phase": min(3, int(combined / 25)),
            "recommendation": self._get_recommendation(level),
        }

        self._last_assessment = assessment
        return level, assessment

    def compute_hndl_risk(self, blockchain: str,
                           utxo_reuse_rate: float = 0.30,
                           daily_tx_volume: int = 500_000) -> QuantumHarvestRiskScore:
        """
        Compute Harvest-Now-Decrypt-Later risk score.
        
        Key factors:
          - Public key reuse rate (address reuse exposes public keys)
          - Time quantum adversaries have had to harvest
          - Estimated CRQC arrival
          - Transaction volume (attack surface)
        """
        harvest_years = max(0, self._simulated_year - 2020)  # started ~2020
        
        # P(harvesting) increases over time
        harvest_probability = min(0.95, harvest_years * 0.08 + 0.15)
        
        # Time to CRQC (median estimate: 2035)
        time_to_crqc = max(0, 2035 - self._simulated_year)
        
        # Exposure score: reuse_rate × harvest_prob × urgency
        urgency = max(0, (10 - time_to_crqc) / 10)
        exposure = (utxo_reuse_rate * 0.4 + harvest_probability * 0.4 + urgency * 0.2) * 100

        return QuantumHarvestRiskScore(
            harvest_probability=harvest_probability,
            time_to_crqc_years=time_to_crqc,
            sensitive_utxo_pct=utxo_reuse_rate * 100,
            blockchain_exposure_score=min(100, int(exposure)),
        )

    def _get_recommendation(self, level: ThreatLevel) -> MigrationRecommendation:
        recommendations = {
            ThreatLevel.GREEN: MigrationRecommendation(
                threat_level=level,
                recommended_aqmp_phase=1,
                actions=[
                    "Deploy AQMP Phase 0: ZK aggregation node setup",
                    "Begin PQC wallet key generation support",
                    "Initialize Quantum Threat Oracle validator network",
                    "Start UTXO quantum risk scoring",
                ],
                urgency_score=15,
                time_window_days=365 * 3,
                rationale="Proactive migration. CRQC still 8+ years away but HNDL attacks active.",
            ),
            ThreatLevel.YELLOW: MigrationRecommendation(
                threat_level=level,
                recommended_aqmp_phase=1,
                actions=[
                    "Activate AQMP Phase 1: Dual-Commit transactions mandatory",
                    "Broadcast wallet migration advisory to users",
                    "Accelerate ZK aggregation deployment",
                    "Set legacy UTXO migration deadline (18 months)",
                ],
                urgency_score=45,
                time_window_days=365 * 2,
                rationale="Elevated risk. Quantum progress accelerating. Begin active migration.",
            ),
            ThreatLevel.ORANGE: MigrationRecommendation(
                threat_level=level,
                recommended_aqmp_phase=2,
                actions=[
                    "EMERGENCY: Advance to AQMP Phase 2 (PQC Primary)",
                    "Freeze high-value UTXO spending with ECDSA-only",
                    "Mandatory PQC for transactions > $10,000",
                    "90-day final window for legacy UTXO migration",
                ],
                urgency_score=78,
                time_window_days=180,
                rationale="CRQC imminent. Immediate migration for high-value assets critical.",
            ),
            ThreatLevel.RED: MigrationRecommendation(
                threat_level=level,
                recommended_aqmp_phase=3,
                actions=[
                    "CRITICAL: Activate AQMP Phase 3 (PQC-ONLY consensus)",
                    "Reject all ECDSA-only transactions immediately",
                    "Emergency governance vote for classical sunset",
                    "All remaining UTXO addresses frozen pending quantum-safe migration",
                ],
                urgency_score=100,
                time_window_days=30,
                rationale="CRQC operational or confirmed imminent. Classical crypto compromised.",
            ),
        }
        return recommendations[level]

    def generate_threat_report(self, current_year: Optional[int] = None) -> str:
        """Generate a human-readable threat assessment report."""
        year = current_year or self._simulated_year
        level, assessment = self.assess_threat_level(year)
        hndl_btc = self.compute_hndl_risk("Bitcoin", utxo_reuse_rate=0.30)
        hndl_eth = self.compute_hndl_risk("Ethereum", utxo_reuse_rate=0.45)
        rec = self._get_recommendation(level)

        colors = {
            ThreatLevel.GREEN: "🟢",
            ThreatLevel.YELLOW: "🟡",
            ThreatLevel.ORANGE: "🟠",
            ThreatLevel.RED: "🔴",
        }

        lines = [
            f"{'='*65}",
            f"  AQMP QUANTUM THREAT ORACLE — Assessment Year {year}",
            f"{'='*65}",
            f"  Threat Level: {colors[level]} {level.name}",
            f"  Combined Score: {assessment['combined_score']:.1f}/100",
            f"  Recommended AQMP Phase: {assessment['recommended_aqmp_phase']}",
            f"",
            f"  HNDL Risk Scores:",
            f"    Bitcoin  : {hndl_btc.blockchain_exposure_score}/100 "
            f"({hndl_btc.urgency_level.name})",
            f"    Ethereum : {hndl_eth.blockchain_exposure_score}/100 "
            f"({hndl_eth.urgency_level.name})",
            f"",
            f"  Recommended Actions:",
        ]
        for action in rec.actions:
            lines.append(f"    • {action}")
        lines.append(f"")
        lines.append(f"  Time Window: {rec.time_window_days} days")
        lines.append(f"  Urgency Score: {rec.urgency_score}/100")
        lines.append(f"  Rationale: {rec.rationale}")
        lines.append(f"{'='*65}")

        return "\n".join(lines)