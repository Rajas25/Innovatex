import XssLab from '../../labs/XssLab';
import SqlInjectionLab from '../../labs/SqlInjectionLab';
import IdorLab from '../../labs/IdorLab';
import BflaLab from '../../labs/BflaLab';
import JwtLab from '../../labs/JwtLab';
import MassAssignmentLab from '../../labs/MassAssignmentLab';
import RateLimitLab from '../../labs/RateLimitLab';
import DataExposureLab from '../../labs/DataExposureLab';
import PrototypePollutionLab from '../../labs/PrototypePollutionLab';
import HeadersLab from '../../labs/HeadersLab';
import TokenStorageLab from '../../labs/TokenStorageLab';
import LogRedactionLab from '../../labs/LogRedactionLab';

export const LAB_COMPONENTS = {
  xss: XssLab,
  sqli: SqlInjectionLab,
  idor: IdorLab,
  bfla: BflaLab,
  jwt: JwtLab,
  mass_assignment: MassAssignmentLab,
  rate_limit: RateLimitLab,
  data_exposure: DataExposureLab,
  prototype_pollution: PrototypePollutionLab,
  headers: HeadersLab,
  token_storage: TokenStorageLab,
  log_redaction: LogRedactionLab,
};