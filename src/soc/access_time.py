"""Time context is evidence, never an authentication or blocking decision."""
from datetime import datetime, timedelta, timezone
from functools import lru_cache
import hashlib
import json
from pathlib import Path

KST = timezone(timedelta(hours=9))
LOGIN_ATTEMPTS = frozenset({'login_success','login_failed','login_source_denied','login_blocked'})


@lru_cache(maxsize=1)
def load_policy():
    policy = json.loads(Path(__file__).with_name('access_time_policy.json').read_text(encoding='utf-8'))
    if policy['timezone'] != 'Asia/Seoul' or not 0 <= policy['day_start_hour'] < policy['night_start_hour'] <= 23:
        raise ValueError('Invalid access-time policy')
    policy['policy_id'] = policy['version'] + ':' + hashlib.sha256(json.dumps(policy,sort_keys=True).encode()).hexdigest()[:12]
    return policy


def parse_time(stamp):
    dt = stamp if isinstance(stamp,datetime) else datetime.fromisoformat(str(stamp).replace('Z','+00:00'))
    if dt.tzinfo is None:
        raise ValueError('An explicit timezone is required')
    return dt


def evaluate_access_time(stamp, username=None, policy=None):
    policy = policy or load_policy()
    local = parse_time(stamp).astimezone(KST)
    night = local.hour >= policy['night_start_hour'] or local.hour < policy['day_start_hour']
    weekend = local.weekday() >= 5
    holiday = local.date().isoformat() in policy.get('holidays', [])
    approved = None
    for item in policy.get('exceptions', []):
        # Only explicit account + bounded interval + approval record qualify.
        if (username and item.get('username') == username and item.get('approved_by') and item.get('reason')
                and item.get('starts_at') and item.get('ends_at')
                and parse_time(item['starts_at']) <= local < parse_time(item['ends_at'])):
            approved = {k:item[k] for k in ('username','approved_by','reason','starts_at','ends_at')}
            break
    return {'policy_id':policy.get('policy_id',policy['version']), 'local_time':local.isoformat(),
            'timezone':'Asia/Seoul', 'day_start_hour':policy['day_start_hour'], 'night_start_hour':policy['night_start_hour'],
            'night':night, 'weekend':weekend, 'holiday':holiday,
            'outside':night or weekend or holiday, 'exception':approved,
            'requires_review':(night or weekend or holiday) and not approved}


def event_time_context(event):
    get = event.get if isinstance(event,dict) else lambda k,d=None:getattr(event,k,d)
    if get('source') != 'erp' or get('event_type') not in LOGIN_ATTEMPTS:
        return {}
    details = get('details',{}) or {}
    saved = get('access_time') or details.get('access_time')
    if saved:
        return saved
    result = evaluate_access_time(get('event_ts_utc'),get('username'))
    result['historical_reevaluation'] = True
    return result


def case_time_context(incident):
    contexts = [event_time_context(e) for e in incident.evidence_events]
    outside = [c for c in contexts if c.get('outside')]
    # Replay/synthetic and untrusted input never raise operational priority.
    priority = any(event_time_context(e).get('requires_review') and e.ingest_mode=='live' and e.client_ip_trusted
                   for e in incident.evidence_events)
    return outside, priority


def night_bands(start, end):
    """Normalized chart coordinates for 23:00–07:00, with no holiday shading."""
    start,end=parse_time(start),parse_time(end)
    if end<=start: return []
    policy=load_policy()
    cursor=(start.astimezone(KST)-timedelta(days=1)).replace(hour=policy['night_start_hour'],minute=0,second=0,microsecond=0)
    bands=[]
    while cursor<end:
        stop=(cursor+timedelta(days=1)).replace(hour=policy['day_start_hour'])
        a,b=max(start,cursor),min(end,stop)
        if b>a: bands.append([(a-start)/(end-start),(b-start)/(end-start)])
        cursor+=timedelta(days=1)
    return bands
