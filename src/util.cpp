#include "util.h"

long NX;
int NY;
int K_IND;
int N_BLOCK;
ZZ template_bit_or;
HEnc::PTxt cof_pt;

void packing(ZZ &dst, vector<raw_data>& data, vector<int64_t>& pad_list)
{
    assert(data.size() <= PACKAGE_SIZE);
    assert(data.size() == pad_list.size());
    dst = 0;
    for (int i = 0; i < data.size(); i++)
    {
        NTL::LeftShift(dst, dst, PACKAGE_LEN);
        NTL::bit_or(dst, dst, data[i] + pad_list[i]);
    }
    NTL::bit_or(dst, dst, template_bit_or);
}

void packing(ZZ &dst, vector<ZZ> &data, Paillier::Encryptor &enc)
{
    assert(data.size() <= PACKAGE_SIZE);
    dst = 0;
    HEnc::CTxt ct1;
    ct1.set_ct(data[0]);
    for (int i = 1; i < data.size(); i++)
    {
        HEnc::CTxt ct;
        ct.set_ct(data[i]);
        enc.he_mul(ct1, cof_pt, ct1);
        enc.he_add(ct1, ct, ct1);
    }
    dst = ct1.get_ct();
}

void unpacking(vector<ZZ> &dst, ZZ &src, int len)
{
    dst.clear();
    int data_bits = 40;
    for (int i = 0; i < len; i++)
    {
        ZZ t = trunc_ZZ(src, data_bits);
        dst.emplace_back(t);
        NTL::RightShift(src, src, PACKAGE_LEN);
    }
    reverse(dst.begin(), dst.end());
}

void ZZ2char(ZZ &src, unsigned char *dst)
{
    long lbits = NTL::NumBits(src);
    long lbytes = (lbits + 7) / 8;
    NTL::BytesFromZZ(dst, src, lbytes);
}

void init_packing()
{
    template_bit_or = 0;
    ZZ aux_templace;
    NTL::LeftShift(aux_templace, ZZ(1), 4 * 8 + 17);
    ZZ cof;
    NTL::LeftShift(cof, ZZ(1), PACKAGE_LEN);
    cof_pt.set_pt(cof);
    NTL::bit_or(template_bit_or, template_bit_or, aux_templace);
    for (int i = 1; i < PACKAGE_SIZE; i++)
    {
        NTL::LeftShift(aux_templace, aux_templace, PACKAGE_LEN);
        NTL::bit_or(template_bit_or, template_bit_or, aux_templace);
    }
    // cout << "@@@" << template_bit_or << endl;
}