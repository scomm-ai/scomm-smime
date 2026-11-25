use scomm_smime::*;
use std::ptr;

fn take(f: impl FnOnce(*mut *mut u8, *mut usize) -> i32) -> (i32, Vec<u8>) {
    let (mut out, mut len) = (ptr::null_mut(), 0);
    let code = f(&mut out, &mut len);
    let bytes = if out.is_null() {
        vec![]
    } else {
        let bytes = unsafe { std::slice::from_raw_parts(out, len).to_vec() };
        unsafe { scomm_smime_buffer_free(out, len) };
        bytes
    };
    (code, bytes)
}

#[test]
fn nist_profiles_generate_and_sign_through_c_abi() {
    let userid = b"Native Curves <curves@example.com>";
    for (profile, alg) in [
        (4, "smime-ecdsa-p256-sha256"),
        (5, "smime-ecdsa-p384-sha384"),
        (6, "smime-ecdsa-p521-sha512"),
    ] {
        let (mut p, mut pl, mut s, mut sl, mut j, mut jl) =
            (ptr::null_mut(), 0, ptr::null_mut(), 0, ptr::null_mut(), 0);
        assert_eq!(
            unsafe {
                scomm_smime_generate_with_validity(
                    userid.as_ptr(),
                    userid.len(),
                    ptr::null(),
                    0,
                    profile,
                    2,
                    &mut p,
                    &mut pl,
                    &mut s,
                    &mut sl,
                    &mut j,
                    &mut jl,
                )
            },
            0
        );
        let public = unsafe { std::slice::from_raw_parts(p, pl).to_vec() };
        let secret = unsafe { std::slice::from_raw_parts(s, sl).to_vec() };
        for (ptr, len) in [(p, pl), (s, sl), (j, jl)] {
            unsafe { scomm_smime_buffer_free(ptr, len) };
        }
        let data = b"FFI NIST signing";
        let (code, sig) = take(|out, len| unsafe {
            scomm_smime_sign_detached(
                data.as_ptr(),
                data.len(),
                secret.as_ptr(),
                secret.len(),
                ptr::null(),
                0,
                alg.as_ptr(),
                alg.len(),
                out,
                len,
            )
        });
        assert_eq!(code, 0);
        let mut valid = 0;
        assert_eq!(
            unsafe {
                scomm_smime_verify(
                    data.as_ptr(),
                    data.len(),
                    sig.as_ptr(),
                    sig.len(),
                    public.as_ptr(),
                    public.len(),
                    &mut valid,
                )
            },
            0
        );
        assert_eq!(valid, 1);
    }
}

#[test]
fn unknown_curve_profile_is_refused_without_output() {
    let userid = b"curves@example.com";
    let (mut p, mut pl, mut s, mut sl, mut j, mut jl) =
        (ptr::null_mut(), 0, ptr::null_mut(), 0, ptr::null_mut(), 0);
    assert_ne!(
        unsafe {
            scomm_smime_generate(
                userid.as_ptr(),
                userid.len(),
                ptr::null(),
                0,
                99,
                &mut p,
                &mut pl,
                &mut s,
                &mut sl,
                &mut j,
                &mut jl,
            )
        },
        0
    );
    assert!(p.is_null() && s.is_null() && j.is_null());
}
