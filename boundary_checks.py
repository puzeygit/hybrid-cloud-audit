"""Граничные проверки учебного механизма; входы задаются отдельно от предикатов."""
from copy import deepcopy
from datetime import timedelta
from pathlib import Path
import json
import audit_core as a
import control_examples as c
ROOT = Path(__file__).resolve().parent
RULES = {r.id: r for r in a.RULES}

def run():
    cases = c.create_cases(); tests = []
    def add(rule_id, attrs, expected, label, exceptions=None):
        r = deepcopy(next(x['resource'] for x in cases if x['rule_id'] == rule_id and x['state'] == 'correct'))
        r['attributes'].update(attrs)
        result = a.assess(RULES[rule_id], r, exceptions or [], a.NOW)
        tests.append({'id':f'B-{len(tests)+1:02}', 'rule_id':rule_id, 'condition':label,
                      'expected':expected, 'actual':result.status, 'passed':result.status == expected,
                      'resource':r, 'exceptions':exceptions or []})
    def network(protocol='tcp', cidr='0.0.0.0/0', low=22, high=22):
        return {'ingress':[{'cidr':cidr,'protocol':protocol,'port_from':low,'port_to':high}]}
    add('NET-01',network(cidr='::/0'),'FAIL','IPv6 ::/0; TCP 22')
    add('NET-01',network(low=0,high=65535),'FAIL','IPv4 /0; TCP 0–65535')
    add('NET-01',network(low=3389,high=3389),'FAIL','IPv4 /0; TCP 3389')
    add('NET-01',network(low=443,high=443),'PASS','IPv4 /0; только TCP 443')
    add('NET-01',network(protocol='udp'),'PASS','IPv4 /0; UDP 22 вне запрета TCP')
    add('NET-01',network(protocol='tpc'),'ERROR','Неизвестный protocol=tpc')
    add('NET-01',network(low=22,high=21),'ERROR','Обратный диапазон портов 22–21')
    add('IAM-02',{'key_created_at':(a.NOW-timedelta(days=90)).isoformat()},'PASS','Возраст ключа ровно 90 суток')
    add('IAM-02',{'key_created_at':(a.NOW-timedelta(days=90,seconds=1)).isoformat()},'FAIL','Возраст ключа 90 суток + 1 с')
    add('IAM-02',{'key_created_at':(a.NOW+timedelta(seconds=1)).isoformat()},'ERROR','Ключ датирован будущим')
    add('DATA-01',{'collected_at':(a.NOW-timedelta(hours=24)).isoformat()},'PASS','Возраст снимка ровно 24 часа')
    add('DATA-01',{'collected_at':(a.NOW-timedelta(hours=24,seconds=1)).isoformat()},'UNKNOWN','Возраст снимка 24 часа + 1 с')
    add('DATA-01',{'collected_at':(a.NOW+timedelta(seconds=1)).isoformat()},'ERROR','Снимок датирован будущим')
    add('K8S-01',{'privileged':'false'},'ERROR','Логическое поле заменено строкой')
    add('LOG-02',{'retention_days':True},'ERROR','Срок хранения заменен bool')
    add('DATA-01',{'collected_at':'2026-10-14T11:00:00'},'ERROR','Дата без часового пояса')
    add('STO-01',{'classification':'unknown'},'ERROR','Классификация вне схемы')
    add('STO-01',{'classification':None},'UNKNOWN','Классификация отсутствует')
    r=deepcopy(cases[38]['resource']); e=deepcopy(cases[38]['exceptions']); e[0]['valid_until']=a.NOW.isoformat()
    result=a.assess(RULES['NET-01'],r,e,a.NOW)
    tests.append({'id':'B-19','rule_id':'NET-01','condition':'t = valid_until: исключение не действует',
                  'expected':'FAIL; без исключения','actual':result.status+'; '+('без исключения' if result.exception_id is None else result.exception_id),
                  'passed':result.status=='FAIL' and result.exception_id is None,'resource':r,'exceptions':e})
    records=a.load_exports([ROOT/'private.json',ROOT/'public.json'])
    exc=[e for x in cases for e in x['exceptions']]
    _,changed,after,_=c.integration_checks(records,exc)
    result=next(x for x in after if x.resource_id=='private:CASE-39' and x.rule_id=='NET-01')
    tests.append({'id':'B-20','rule_id':'NET-01','condition':'Повторная проверка сохраняет EX-39',
                  'expected':'FAIL; EX-39','actual':result.status+'; '+str(result.exception_id),
                  'passed':result.status=='FAIL' and result.exception_id=='EX-39'})
    assert len(tests)==20 and all(x['passed'] for x in tests), tests
    (ROOT/'boundary_protocol.json').write_text(json.dumps({'engine_version':a.VERSION,
        'evaluation_time':a.NOW.isoformat(),'tests':tests},ensure_ascii=False,indent=2))
    print('Граничные проверки: 20 из 20.')
if __name__ == '__main__':run()
