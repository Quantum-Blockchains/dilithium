window.SIDEBAR_ITEMS = {"constant":[["K",""],["L",""]],"fn":[["k_add","Add vectors of polynomials of length K. No modular reduction is performed."],["k_caddq","For all coefficients of polynomials in vector of length K add Q if coefficient is negative."],["k_chknorm","Check infinity norm of polynomials in vector of length K. Assumes input coefficients to be standard representatives. Returns 0 if norm of all polynomials are strictly smaller than B and 1 otherwise."],["k_decompose",""],["k_invntt_tomont","Inverse NTT and multiplication by 2^{32} of polynomials in vector of length K. Input coefficients need to be less than 2*Q."],["k_make_hint",""],["k_ntt","Forward NTT of all polynomials in vector of length K. Output coefficients can be up to 16*Q larger than input coefficients."],["k_pack_w1",""],["k_pointwise_poly_montgomery",""],["k_power2round","For all coefficients a of polynomials in vector of length K, compute a0, a1 such that a mod Q = a1*2^D + a0 with -2^{D-1} < a0 <= 2^{D-1}. Assumes coefficients to be standard representatives."],["k_reduce","Reduce coefficients of polynomials in vector of length K to representatives in [0,2*Q]."],["k_shiftl","Multiply vector of polynomials of Length K by 2^D without modular reduction. Assumes input coefficients to be less than 2^{32-D}."],["k_sub","Subtract vectors of polynomials of length K. Assumes coefficients of polynomials in second input vector to be less than 2*Q. No modular reduction is performed."],["k_uniform_eta",""],["k_use_hint",""],["l_add","Add vectors of polynomials of length L. No modular reduction is performed."],["l_chknorm",""],["l_invntt_tomont",""],["l_ntt","Forward NTT of all polynomials in vector of length L. Output coefficients can be up to 16*Q larger than input coefficients."],["l_pointwise_acc_montgomery","Pointwise multiply vectors of polynomials of length L, multiply resulting vector by 2^{-32} and add (accumulate) polynomials in it. Input/output vectors are in NTT domain representation. Input coefficients are assumed to be less than 22Q. Output coeffcient are less than 2L*Q."],["l_pointwise_poly_montgomery",""],["l_reduce",""],["l_uniform_eta",""],["l_uniform_gamma1",""],["matrix_expand","Implementation of ExpandA. Generates matrix A with uniformly random coefficients a_{i,j} by performing rejection sampling on the output stream of SHAKE128(rho|j|i)."],["matrix_pointwise_montgomery",""]],"struct":[["Polyveck",""],["Polyvecl",""]]};