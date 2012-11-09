import nfs4_pack
import nfs4_const

# Static FATTR4 dictionaries that are created from nfs4_const data
attr2bitnum = {}
bitnum2attr = {}
bitnum2packer = {}
bitnum2unpacker = {}

def set_attrbit_dicts():
    """Set global dictionaries manipulating attribute bit positions.

    Note: This function uses introspection. It assumes an entry
    in nfs4_const.py is an attribute if it is named FATTR4_<something>. 

    Returns {"type": 1, "fh_expire_type": 2,  "change": 3 ...}
            { 1: "type", 2: "fh_expire_type", 3: "change", ...}
            { 1: "pack_fattr4_type", 2: "pack_fattr4_fh_expire_type", ...}
            { 1: "unpack_fattr4_type", 2: "unpack_fattr4_fh_expire_type", ...}
    """
    global attr2bitnum, bitnum2attr, bitnum2packer, bitnum2unpacker
    for name in dir(nfs4_const):
        if name.startswith("FATTR4_"):
            value = getattr(nfs4_const, name)
            # Sanity checking. Must be integer. 
            assert(type(value) is int)
            attrname = name[7:].lower()
            attr2bitnum[attrname] = value
            bitnum2attr[value] = attrname
            bitnum2packer[value] = "pack_fattr4_%s" % attrname
            bitnum2unpacker[value] = "unpack_fattr4_%s" % attrname
# Actually set the dictionaries
set_attrbit_dicts()

class FancyNFS4Unpacker(nfs4_pack.NFS4Unpacker):
    def filter_bitmap4(self, data):
        """Put bitmap into single long, instead of array of 32bit chunks"""
        out = 0L
        shift = 0
        for i in data:
            out |= (long(i) << shift)
            shift += 32
        return out

    def filter_fattr4(self, data):
        """Return as dict, instead of opaque attrlist"""
        return fattr2dict(data)

    def filter_layout_content4(self, data):
        """Unpack layout content"""
        if data.loc_type == nfs4_const.LAYOUT4_NFSV4_1_FILES:
            u = FancyNFS4Unpacker(data.loc_body)
            data.loc_body = u.unpack_nfsv4_1_file_layout4()
        return data

    def filter_device_addr4(self, data):
        """Unpack layout device addr"""
        if data.da_layout_type == nfs4_const.LAYOUT4_NFSV4_1_FILES:
            u = FancyNFS4Unpacker(data.da_addr_body)
            data.da_addr_body = u.unpack_nfsv4_1_file_layout_ds_addr4()
        return data
            
def fattr2dict(obj):
    """Convert a fattr4 object to a dictionary with attribute name and values.

    Returns a dictionary of form {bitnum:value}
    """
    result = {}
    list = bitmap2list(obj.attrmask)
    unpacker = FancyNFS4Unpacker(obj.attr_vals)
    for bitnum in list:
        result[bitnum] = getattr(unpacker, bitnum2unpacker[bitnum])()
    unpacker.done()
    return result

def bitmap2list(bitmap):
    """Return (sorted) list of bit numbers set in bitmap"""
    out = []
    bitnum = 0
    while bitmap:
        if bitmap & 1:
            out.append(bitnum)
        bitnum += 1
        bitmap >>= 1
    return out

