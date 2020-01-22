from neuropil import NeuropilNode, NeuropilCluster, neuropil, np_token, np_message

class TestHelper():


    @staticmethod
    def authn_allow_all(node:NeuropilNode, token:np_token):    
        #print("{node}: {type}: {token} {id}".format(node=node.get_fingerprint(), type="authn", token=token.subject, id=token.get_fingerprint()))
        return True

    @staticmethod
    def authz_allow_all(node:NeuropilNode,token:np_token):
        #print("{node}: {type}: {token} {id}".format(node=node.get_fingerprint(),type="authz", token=token.subject, id=token.get_fingerprint()))
        return True

    @staticmethod
    def acc_allow_all(node:NeuropilNode, token:np_token):
        #print("{node}: {type}: {token}".format(node=node.get_fingerprint(), type="acc", token=token.subject))
        return True