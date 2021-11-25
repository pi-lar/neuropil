from pydantic import BaseModel, constr
from pydantic.types import UUID5

from typing import List, NamedTuple, Set, Tuple


class np_dhkey(BaseModel):
    '''a blake2b hash value of: the signature of an identity, a message subject, a string. Anything that you would like to hash'''
    data: bytes(constr(min_length=32, max_length=32))

class np_bloom_block(BaseModel):
    '''
    a bloom block is a clk hash value. neuropil uses a specific construction based on four different areas where values are added.
    each block is 255 * 2bytes long. 1byte captures the count, the seconf bytes capture the "age" of the added item.
    '''
    block: bytes

class np_bloom(BaseModel):
    '''
    The neuropil bloom filter is a special construction of a clk hash value. It can be used to represent a PPRL link to a resource or document,
    and is derived from this resource or document by applying minhash, skip-gram, k-mer algorithms in a specific way for this type of resource. 
    unlike the official clk_hash our bloom filter is constructed with the concatenation of 4 np_bloom_blocks, which results in a better
    distribution of items across the bloom filter. Nevertheless, the bloom filter needs to reach a certain fill level. in our prototype
    each filter is thus receiving it's input from 256 minhash signature, which should guarantee the needed usage.
    '''
    blocks: Set[np_bloom_block]

class np_attribute(NamedTuple):
    '''
    You know this element already, a key-value used  as an attribute
    '''
    key: str
    value: bytes

class np_token(BaseModel):
    '''
    a np_token describes the resource that a user can search for. It contains a set of attributes (max 10k) to better describe teh resource
    '''
    uuid: UUID5
    subject: str
    issuer: bytes[32]
    realm: bytes[32]
    audience: bytes[32]
    valid_from: float
    issued_at: float
    expires_at: float
    public_key: bytes[32]
    signature: bytes[32]
    attributes: List[np_attribute]
    attributes_signature: bytes[32]

class np_index(BaseModel):
    ''' 
    a np_index is the distributed hash value that is used to locate a search entry.
    the lower_dhkey is derived along the np_bloom filter and identifies the position in teh DHT where the search_entry should be stored.
    '''
    lower_dhkey: np_dhkey
    clk_hash: np_bloom

class np_searchentry(BaseModel):
    '''
    a searchentry is the combintaion fo an nmp_index and an np_token. that's it ...
    '''
    search_index: np_index
    intent: np_token

class np_searchquery(BaseModel):
    '''
    a searchquery is identical to a searchentry. we just add ans query_id and an result_idx to deliver responses (search results) 
    to the correct system.
    '''
    query_id: int
    result_idx: np_dhkey
    query_entry: np_searchentry

class np_searchresult(BaseModel):
    '''
    a searchresult is composed of the np_token from the search_entry. It also contains the similarity to the searchquery and an hit_counter.
    The hit_counter indicates how of the token has been found during the query (across different tables and nodes in the DHT).
    In general: the higher teh hit counter and the similarity, the better the result
    The label is just extracted from the np_attributes. It depends on the datatype which attribute is uased as the label.
    '''
    hit_counter: int  # how often this search was found for this item
    label: str        # a label for the searchentry, taken from the attributes of teh intent token
    similarity: float # the similarity / probability towards the query
    intent: np_token  # the intent token describing the resource / searchentry
