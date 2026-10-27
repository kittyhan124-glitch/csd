"""TV4 oracle: exact byte matches, overlaps, original pattern IDs.

No student algorithm is imported here. Unicode normalization belongs to
tv4.preprocessing; raw binary data must not be decoded implicitly.
"""
from bisect import bisect_left
from collections.abc import Iterable

MASK64=(1<<64)-1


def validate_inputs(text,patterns):
    if not isinstance(text,(bytes,bytearray)):
        raise TypeError('text must be bytes or bytearray')
    if isinstance(patterns,(str,bytes,bytearray)):
        raise TypeError('patterns must be an iterable of byte patterns')
    pats=tuple(patterns)
    if not pats:
        raise ValueError('pattern set must not be empty')
    for p in pats:
        if not isinstance(p,(bytes,bytearray)):
            raise TypeError('each pattern must be bytes or bytearray')
        if not p:
            raise ValueError('empty pattern is not allowed')
    return bytes(text),tuple(bytes(p) for p in pats)


def iter_matches(text,patterns):
    """Validate immediately; return a lazy, per-pattern bytes.find iterator."""
    data,pats=validate_inputs(text,patterns)

    def generate():
        for pid,p in enumerate(pats):
            start=0
            while True:
                pos=data.find(p,start)
                if pos<0:
                    break
                yield pos,pid
                start=pos+1
    return generate()


def oracle_find(text,patterns):
    """Sorted full list; duplicate patterns retain distinct input IDs."""
    return sorted(iter_matches(text,patterns))


def checksum(matches):
    count=check=0
    for pos,pid in matches:
        if not isinstance(pos,int) or not isinstance(pid,int) or pos<0 or pid<0:
            raise ValueError('matches must contain nonnegative integer positions and IDs')
        count+=1
        check=(check+(pos+1)*1_000_003+pid)&MASK64
    return {'count':count,'check':check}


def summarize_matches(text,patterns,matches):
    """Logical LF lines incl. final empty line; reject LF-containing patterns."""
    data,pats=validate_inputs(text,patterns)
    if any(b'\n' in p for p in pats):
        raise ValueError('line metrics require patterns without LF')
    newlines=[i for i,b in enumerate(data) if b==10]
    flagged=set()
    count=check=0
    for pos,pid in matches:
        if not isinstance(pos,int) or not isinstance(pid,int):
            raise ValueError('match position and ID must be integers')
        if not (0<=pid<len(pats) and 0<=pos<=len(data)-len(pats[pid])):
            raise ValueError('match position or ID out of bounds')
        if data[pos:pos+len(pats[pid])]!=pats[pid]:
            raise ValueError('reported match does not equal its pattern')
        count+=1
        check=(check+(pos+1)*1_000_003+pid)&MASK64
        flagged.add(bisect_left(newlines,pos))
    return {'count':count,'check':check,'lines_flagged':len(flagged),
            'lines_total':len(newlines)+1}
