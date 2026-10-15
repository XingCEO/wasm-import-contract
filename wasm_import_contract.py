"""Inspect a Wasm module’s host requirements without instantiating it."""

class Reader:
    def __init__(self,data): self.data=data; self.pos=0
    def take(self,n):
        if n<0 or self.pos+n>len(self.data): raise ValueError('truncated Wasm binary')
        out=self.data[self.pos:self.pos+n]; self.pos+=n; return out
    def byte(self): return self.take(1)[0]
    def uint(self):
        result=0
        for i in range(5):
            b=self.byte()
            if i==4 and b&0xf0: raise ValueError('u32 LEB128 overflow')
            result|=(b&127)<<(7*i)
            if not b&128: return result
        raise ValueError('invalid LEB128')
    def name(self):
        try: return self.take(self.uint()).decode('utf-8')
        except UnicodeDecodeError as error: raise ValueError('invalid UTF-8 import name') from error
    def limits(self):
        flags=self.uint()
        if flags not in (0,1,3): raise ValueError('unsupported limits flags')
        low=self.uint(); high=self.uint() if flags&1 else None
        if high is not None and high<low: raise ValueError('maximum below minimum')
        return {'minimum':low,'maximum':high,'shared':bool(flags&2)}


def imports(binary):
    reader=Reader(binary)
    if reader.take(8)!=b'\x00asm\x01\x00\x00\x00': raise ValueError('expected core Wasm version 1')
    result=[]; seen=False
    while reader.pos<len(binary):
        section=reader.byte(); payload=Reader(reader.take(reader.uint()))
        if section!=2: continue
        if seen: raise ValueError('duplicate import section')
        seen=True
        for _ in range(payload.uint()):
            module,name,kind=payload.name(),payload.name(),payload.byte()
            record={'module':module,'name':name}
            if kind==0: record.update(kind='function',type_index=payload.uint())
            elif kind==1:
                ref=payload.byte()
                if ref not in (0x70,0x6f): raise ValueError('unsupported table reference type')
                record.update(kind='table',reference_type=hex(ref),limits=payload.limits())
            elif kind==2: record.update(kind='memory',limits=payload.limits())
            elif kind==3:
                value,mutable=payload.byte(),payload.byte()
                if value not in (0x7f,0x7e,0x7d,0x7c,0x7b,0x70,0x6f) or mutable not in (0,1): raise ValueError('unsupported global type')
                record.update(kind='global',value_type=hex(value),mutable=bool(mutable))
            else: raise ValueError('unsupported import kind')
            result.append(record)
        if payload.pos!=len(payload.data): raise ValueError('trailing bytes in import section')
    return result


def analyze(data):
    required=imports(bytes.fromhex(data['wasm_hex'])); host={}; findings=[]
    for item in data.get('host',[]):
        key=(item['module'],item['name'])
        if key in host: raise ValueError('duplicate host binding')
        host[key]=item
    for item in required:
        supplied=host.get((item['module'],item['name']))
        if supplied is None: findings.append({'module':item['module'],'name':item['name'],'kind':'missing_import'})
        elif supplied['kind']!=item['kind']: findings.append({'module':item['module'],'name':item['name'],'kind':'import_kind_mismatch'})
    return {'imports':required,'name_and_kind_match':not findings,'findings':findings,'requires_type_validation':bool(required)}


def main():
    """Analyze a JSON envelope or explicitly selected native files."""
    import argparse
    import json
    import sys
    from pathlib import Path
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', nargs='?', help='JSON input path, or - for stdin')
    parser.add_argument('--wasm', help='Read wasm directly from a local file')
    parser.add_argument('--host', help='JSON array of host bindings')
    args = parser.parse_args()
    native = bool(args.wasm)
    if native and (args.input or not (args.wasm)):
        parser.error('Supply all native file flags, without a positional JSON input')
    if not native and not args.input:
        parser.error('Supply a JSON input or native file flags')
    try:
        if native:
            data = {'wasm_hex': Path(args.wasm).read_bytes().hex(), 'host': json.loads(Path(args.host).read_text()) if args.host else []}
        else:
            raw = sys.stdin.read() if args.input == '-' else Path(args.input).read_text(encoding='utf-8')
            data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError('input must be a JSON object')
        result = analyze(data)
        print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
    except (OSError, ValueError, KeyError, TypeError, OverflowError) as error:
        print(f'Invalid input: {error}', file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
