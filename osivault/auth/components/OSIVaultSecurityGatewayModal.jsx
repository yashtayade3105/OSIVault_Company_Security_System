import React, { useState } from 'react';
import { 
  ShieldCheck, 
  Key, 
  Smartphone, 
  AlertCircle, 
  CheckCircle2, 
  ArrowRight, 
  X, 
  ExternalLink,
  Sparkles,
  Lock,
  Fingerprint,
  RefreshCw,
  Mail,
  Shield,
  Zap,
  Check,
  UserCheck
} from 'lucide-react';
import axios from 'axios';

function bufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let string = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    string += String.fromCharCode(bytes[i]);
  }
  return btoa(string).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64UrlToBuffer(base64url) {
  let padding = '='.repeat((4 - base64url.length % 4) % 4);
  let base64 = (base64url + padding).replace(/\-/g, '+').replace(/_/g, '/');
  let rawData = window.atob(base64);
  let outputArray = new Uint8Array(rawData.length);
  for (let i = 0; i < rawData.length; ++i) {
    outputArray[i] = rawData.charCodeAt(i);
  }
  return outputArray.buffer;
}

export default function OSIVaultSecurityGatewayModal({ isOpen, onClose, onAuthenticated, backendUrl = 'http://localhost:8000' }) {
  const [email, setEmail] = useState('');
  const [step, setStep] = useState('CHECK_EMAIL'); // CHECK_EMAIL, SHOW_OPTIONS, VERIFY_TOTP, TOUCH_YUBIKEY, VERIFIED
  const [mfaData, setMfaData] = useState(null);
  const [totpCode, setTotpCode] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [banner, setBanner] = useState(null);

  if (!isOpen) return null;

  const handleCheckMFAStatus = async (e) => {
    e?.preventDefault();
    if (!email.trim()) {
      setBanner({ type: 'error', message: 'Please enter your registered Email ID or Username.' });
      return;
    }

    setLoading(true);
    setBanner(null);

    try {
      const res = await axios.get(`${backendUrl}/osivault/auth/api/user/mfa-status/?email=${encodeURIComponent(email.trim())}`);
      const data = res.data;

      if (data.status === 'success') {
        setMfaData(data);
        setStep('SHOW_OPTIONS');
        setBanner({ type: 'info', message: data.message });
      } else {
        setBanner({ type: 'error', message: data.message || 'Failed to check MFA status.' });
      }
    } catch (err) {
      setBanner({ 
        type: 'error', 
        message: err.response?.data?.message || `Could not connect to OSIVault Auth Backend (${backendUrl}).` 
      });
    } finally {
      setLoading(false);
    }
  };

  const handleYubiKeyAuthenticate = async () => {
    setLoading(true);
    setStep('TOUCH_YUBIKEY');
    setBanner({ type: 'info', message: 'Fetching YubiKey Assertion Challenge... Please insert YubiKey & touch the golden sensor.' });

    try {
      const optRes = await axios.get(`${backendUrl}/osivault/auth/api/webauthn/assertion/options/?username=${encodeURIComponent(email.trim())}`);
      const optData = optRes.data;

      if (optData.status !== 'success') {
        setBanner({ type: 'error', message: optData.message || 'Failed to initialize YubiKey assertion challenge.' });
        setStep('SHOW_OPTIONS');
        setLoading(false);
        return;
      }

      const opts = optData.options;
      let verifiedCredId = null;

      if (window.PublicKeyCredential && window.navigator.credentials) {
        try {
          const allowCreds = opts.allowCredentials ? opts.allowCredentials.map(c => ({
            id: base64UrlToBuffer(c.id),
            type: 'public-key',
            transports: ['usb', 'nfc', 'internal']
          })) : [];

          const publicKeyOptions = {
            challenge: base64UrlToBuffer(opts.challenge),
            rpId: opts.rpId || window.location.hostname,
            allowCredentials: allowCreds.length > 0 ? allowCreds : undefined,
            userVerification: 'preferred',
            timeout: 60000,
          };

          const assertion = await navigator.credentials.get({ publicKey: publicKeyOptions });
          if (assertion) {
            verifiedCredId = bufferToBase64Url(assertion.rawId);
          }
        } catch (webauthnErr) {
          console.warn('YubiKey assertion exception:', webauthnErr);
        }
      }

      const verifyRes = await axios.post(`${backendUrl}/osivault/auth/api/webauthn/assertion/verify/`, {
        credential_id: verifiedCredId,
        email: email.trim()
      });

      if (verifyRes.data.status === 'success') {
        setBanner({ type: 'success', message: verifyRes.data.message });
        setStep('VERIFIED');
        if (onAuthenticated) onAuthenticated(verifyRes.data);
      } else {
        setBanner({ type: 'error', message: verifyRes.data.message || 'YubiKey verification failed.' });
        setStep('SHOW_OPTIONS');
      }

    } catch (err) {
      setBanner({ type: 'error', message: 'Error verifying YubiKey touch: ' + (err.response?.data?.message || err.message) });
      setStep('SHOW_OPTIONS');
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyTOTP = async (e) => {
    e?.preventDefault();
    if (!totpCode || totpCode.length !== 6) {
      setBanner({ type: 'error', message: 'Please enter a valid 6-digit TOTP code.' });
      return;
    }

    setLoading(true);
    setBanner(null);

    try {
      const res = await axios.post(`${backendUrl}/osivault/auth/api/totp/verify/`, {
        code: totpCode,
        email: email.trim()
      });

      if (res.data.status === 'success') {
        setBanner({ type: 'success', message: res.data.message });
        setStep('VERIFIED');
        if (onAuthenticated) onAuthenticated(res.data);
      } else {
        setBanner({ type: 'error', message: res.data.message || 'Invalid TOTP code.' });
      }
    } catch (err) {
      setBanner({ type: 'error', message: err.response?.data?.message || 'Error verifying TOTP code.' });
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyRecoveryCode = async (e) => {
    e?.preventDefault();
    if (!recoveryCode.trim()) {
      setBanner({ type: 'error', message: 'Please enter a valid emergency recovery code.' });
      return;
    }

    setLoading(true);
    setBanner(null);

    try {
      const res = await axios.post(`${backendUrl}/osivault/auth/api/recovery-codes/verify/`, {
        code: recoveryCode.trim(),
        email: email.trim()
      });

      if (res.data.status === 'success') {
        setBanner({ type: 'success', message: res.data.message });
        setStep('VERIFIED');
        if (onAuthenticated) onAuthenticated(res.data);
      } else {
        setBanner({ type: 'error', message: res.data.message || 'Invalid or already used recovery code.' });
      }
    } catch (err) {
      setBanner({ type: 'error', message: err.response?.data?.message || 'Error verifying recovery code.' });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/60 backdrop-blur-md animate-fadeIn">
      {/* Bright vibrant background gradient blurs */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[30rem] h-[30rem] bg-gradient-to-tr from-purple-400/30 via-indigo-400/20 to-cyan-400/30 blur-3xl rounded-full pointer-events-none" />
      <div className="absolute bottom-1/4 left-1/3 w-96 h-96 bg-amber-400/20 blur-3xl rounded-full pointer-events-none" />

      {/* Bright Modern Colorful Card Container */}
      <div className="relative w-full max-w-xl bg-white/95 border-2 border-slate-200/80 rounded-3xl shadow-2xl overflow-hidden p-6 sm:p-8 space-y-6 backdrop-blur-2xl text-slate-900">
        
        {/* Top Header & Branding */}
        <div className="flex items-start justify-between pb-4 border-b border-slate-100">
          <div className="flex items-center gap-3.5">
            <div className="relative w-12 h-12 rounded-2xl bg-gradient-to-tr from-purple-600 via-indigo-600 to-cyan-500 flex items-center justify-center text-white shadow-xl shadow-purple-500/30 shrink-0">
              <ShieldCheck className="w-6 h-6 text-white" />
              <div className="absolute -top-1 -right-1 w-3.5 h-3.5 bg-cyan-400 border-2 border-white rounded-full animate-ping opacity-90" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-xl font-black text-slate-900 tracking-tight">
                  OSIVault Security Gateway
                </h3>
                <span className="px-3 py-1 rounded-full bg-gradient-to-r from-purple-600 to-indigo-600 text-white text-[10px] font-black tracking-wider uppercase flex items-center gap-1 shadow-sm">
                  <Zap className="w-3 h-3 text-cyan-200" /> Zero-Trust
                </span>
              </div>
              <p className="text-xs text-slate-600 font-semibold mt-0.5">
                Do you want to add extra security to your website platform session?
              </p>
            </div>
          </div>
          <button 
            onClick={onClose}
            className="p-2 rounded-xl text-slate-400 hover:text-slate-800 hover:bg-slate-100 transition-all cursor-pointer"
            title="Close Gateway"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Live Visual Step Progress Indicator */}
        <div className="grid grid-cols-3 gap-2 py-1">
          <div className={`h-2 rounded-full transition-all duration-300 ${
            step === 'CHECK_EMAIL' ? 'bg-gradient-to-r from-purple-600 to-cyan-500 shadow-md shadow-purple-500/30' : 'bg-purple-600'
          }`} />
          <div className={`h-2 rounded-full transition-all duration-300 ${
            step === 'SHOW_OPTIONS' || step === 'TOUCH_YUBIKEY' || step === 'VERIFY_TOTP' ? 'bg-gradient-to-r from-purple-600 to-cyan-500 shadow-md shadow-purple-500/30' : 
            step === 'VERIFIED' ? 'bg-purple-600' : 'bg-slate-100 border border-slate-200'
          }`} />
          <div className={`h-2 rounded-full transition-all duration-300 ${
            step === 'VERIFIED' ? 'bg-gradient-to-r from-emerald-500 to-teal-400 shadow-md shadow-emerald-500/30' : 'bg-slate-100 border border-slate-200'
          }`} />
        </div>

        {/* Dynamic Status Banner */}
        {banner && (
          <div className={`p-4 rounded-2xl text-xs sm:text-sm font-bold flex items-start gap-3 border-2 shadow-md transition-all ${
            banner.type === 'error' ? 'bg-rose-50 text-rose-800 border-rose-200 shadow-rose-100' :
            banner.type === 'success' ? 'bg-emerald-50 text-emerald-800 border-emerald-200 shadow-emerald-100' :
            'bg-indigo-50 text-indigo-900 border-indigo-200 shadow-indigo-100'
          }`}>
            {banner.type === 'error' && <AlertCircle className="w-5 h-5 text-rose-600 shrink-0 mt-0.5" />}
            {banner.type === 'success' && <CheckCircle2 className="w-5 h-5 text-emerald-600 shrink-0 mt-0.5" />}
            {banner.type === 'info' && <Sparkles className="w-5 h-5 text-indigo-600 shrink-0 mt-0.5 animate-pulse" />}
            <span className="leading-relaxed">{banner.message}</span>
          </div>
        )}

        {/* STEP 1: Enter Email ID / Account */}
        {step === 'CHECK_EMAIL' && (
          <form onSubmit={handleCheckMFAStatus} className="space-y-5">
            <div className="space-y-2">
              <label className="block text-xs font-black text-slate-700 uppercase tracking-wider flex items-center justify-between">
                <span>REGISTERED EMAIL ID / ACCOUNT</span>
                <span className="text-[10px] text-purple-600 font-extrabold bg-purple-50 px-2 py-0.5 rounded-md border border-purple-200">Step 1 of 3</span>
              </label>
              <div className="relative">
                <Mail className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-purple-500" />
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="e.g. mh25cv3375@gmail.com"
                  className="w-full pl-12 pr-4 py-4 rounded-2xl bg-slate-50/80 border-2 border-slate-200 text-slate-900 placeholder-slate-400 font-bold text-sm focus:outline-none focus:bg-white focus:border-purple-600 focus:ring-4 focus:ring-purple-600/10 transition-all shadow-inner"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-4 rounded-2xl bg-gradient-to-r from-purple-600 via-indigo-600 to-cyan-500 hover:from-purple-700 hover:to-cyan-600 text-white font-black text-sm shadow-xl shadow-purple-600/30 hover:shadow-purple-600/50 transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin text-cyan-200" />
                  <span>Checking Account Posture...</span>
                </>
              ) : (
                <>
                  <span>Check MFA Security Status</span>
                  <ArrowRight className="w-4 h-4 text-cyan-200" />
                </>
              )}
            </button>

            {/* Bright Micro Feature Badges */}
            <div className="grid grid-cols-3 gap-2 pt-2 text-[11px] font-bold">
              <div className="flex items-center justify-center gap-1.5 p-2.5 rounded-xl bg-purple-50 text-purple-700 border border-purple-200 shadow-sm">
                <Lock className="w-3.5 h-3.5 text-purple-600" />
                <span>FIDO2 Hardware</span>
              </div>
              <div className="flex items-center justify-center gap-1.5 p-2.5 rounded-xl bg-cyan-50 text-cyan-700 border border-cyan-200 shadow-sm">
                <Shield className="w-3.5 h-3.5 text-cyan-600" />
                <span>Replay Guard</span>
              </div>
              <div className="flex items-center justify-center gap-1.5 p-2.5 rounded-xl bg-emerald-50 text-emerald-700 border border-emerald-200 shadow-sm">
                <Zap className="w-3.5 h-3.5 text-emerald-600" />
                <span>Zero-Trust</span>
              </div>
            </div>
          </form>
        )}

        {/* STEP 2: Show Dynamic Options */}
        {step === 'SHOW_OPTIONS' && mfaData && (
          <div className="space-y-4">
            
            {/* Account Info Pill */}
            <div className="flex items-center justify-between p-3.5 rounded-2xl bg-purple-50/80 border-2 border-purple-200 text-xs text-slate-700 font-bold">
              <div className="flex items-center gap-2">
                <UserCheck className="w-4 h-4 text-purple-600" />
                <span>Account: <strong className="text-purple-900">{mfaData.email || email}</strong></span>
              </div>
              <button
                onClick={() => setStep('CHECK_EMAIL')}
                className="text-[11px] font-extrabold text-purple-700 hover:text-purple-900 underline transition-all"
              >
                Change Email
              </button>
            </div>

            {/* Case 1: Account does NOT exist or NO MFA setup */}
            {!mfaData.exists || (!mfaData.has_yubikey && !mfaData.has_totp) ? (
              <div className="p-5 rounded-2xl bg-amber-50 border-2 border-amber-300 space-y-4 shadow-sm">
                <p className="text-xs sm:text-sm text-amber-900 font-bold leading-relaxed">
                  No active YubiKey Hardware or TOTP Authenticator is linked to <strong>{email}</strong> yet.
                </p>
                <a
                  href={`${backendUrl}/osivault/auth/portal/`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="w-full py-3.5 rounded-2xl bg-gradient-to-r from-amber-500 to-yellow-500 hover:from-amber-600 hover:to-yellow-600 text-slate-950 font-black text-xs shadow-lg shadow-amber-500/20 transition-all flex items-center justify-center gap-2 cursor-pointer"
                >
                  <span>Set Up YubiKey & TOTP in OSIVault Portal</span>
                  <ExternalLink className="w-4 h-4" />
                </a>
              </div>
            ) : (
              /* Case 2: User HAS YubiKey and/or TOTP */
              <div className="space-y-3">
                
                {/* Method Selection Header when both exist */}
                {mfaData.has_yubikey && mfaData.has_totp && (
                  <p className="text-xs font-black text-slate-700 tracking-wide uppercase flex items-center gap-1.5 pb-1">
                    <Sparkles className="w-3.5 h-3.5 text-purple-600" />
                    <span>Select Multi-Factor Method (Both Enabled):</span>
                  </p>
                )}

                {/* YubiKey Option */}
                {mfaData.has_yubikey && (
                  <button
                    onClick={handleYubiKeyAuthenticate}
                    disabled={loading}
                    className="w-full p-4 rounded-2xl bg-gradient-to-r from-amber-50/90 via-orange-50/80 to-purple-50/90 hover:from-amber-100 hover:to-purple-100 border-2 border-amber-300/80 hover:border-amber-400 transition-all flex items-center justify-between text-left group cursor-pointer shadow-md hover:shadow-amber-500/20"
                  >
                    <div className="flex items-center gap-3.5">
                      <div className="w-11 h-11 rounded-2xl bg-amber-500 text-white flex items-center justify-center font-bold shrink-0 group-hover:scale-105 transition-transform shadow-md shadow-amber-500/30">
                        <Key className="w-6 h-6 text-white" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-black text-slate-900 group-hover:text-purple-900">
                            Authenticate via YubiKey Hardware
                          </span>
                          <span className="px-2.5 py-0.5 rounded-full bg-amber-500 text-slate-950 text-[10px] font-black shadow-sm">
                            Hardware Sensor
                          </span>
                        </div>
                        <div className="text-xs text-slate-600 font-bold mt-0.5">
                          FIDO2 CTAP2 Touch Contact Verification ({mfaData.yubikey_count || 1} active slot)
                        </div>
                      </div>
                    </div>
                    <Key className="w-5 h-5 text-amber-600 group-hover:translate-x-1 transition-transform" />
                  </button>
                )}

                {/* TOTP Option */}
                {mfaData.has_totp && (
                  <button
                    onClick={() => setStep('VERIFY_TOTP')}
                    disabled={loading}
                    className="w-full p-4 rounded-2xl bg-gradient-to-r from-indigo-50/90 via-purple-50/80 to-cyan-50/90 hover:from-indigo-100 hover:to-cyan-100 border-2 border-indigo-300/80 hover:border-indigo-400 transition-all flex items-center justify-between text-left group cursor-pointer shadow-md hover:shadow-indigo-500/20"
                  >
                    <div className="flex items-center gap-3.5">
                      <div className="w-11 h-11 rounded-2xl bg-indigo-600 text-white flex items-center justify-center font-bold shrink-0 group-hover:scale-105 transition-transform shadow-md shadow-indigo-600/30">
                        <Smartphone className="w-6 h-6 text-white" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-black text-slate-900 group-hover:text-indigo-900">
                            Authenticate via TOTP App
                          </span>
                          <span className="px-2.5 py-0.5 rounded-full bg-indigo-600 text-white text-[10px] font-black shadow-sm">
                            6-Digit Passcode
                          </span>
                        </div>
                        <div className="text-xs text-slate-600 font-bold mt-0.5">
                          Google Authenticator / Authy / 1Password App
                        </div>
                      </div>
                    </div>
                    <Smartphone className="w-5 h-5 text-indigo-600 group-hover:translate-x-1 transition-transform" />
                  </button>
                )}

                {/* Emergency Break-Glass Fallback Option */}
                <div className="pt-2 border-t border-slate-100 text-center">
                  <button
                    type="button"
                    onClick={() => setStep('VERIFY_RECOVERY')}
                    className="text-xs font-bold text-slate-500 hover:text-purple-700 underline transition-all cursor-pointer flex items-center justify-center gap-1.5 mx-auto"
                  >
                    <Shield className="w-3.5 h-3.5 text-slate-400" />
                    <span>Lost phone or YubiKey? Authenticate via Emergency Recovery Code</span>
                  </button>
                </div>

              </div>
            )}
          </div>
        )}

        {/* STEP 3A: Waiting for YubiKey Touch Contact */}
        {step === 'TOUCH_YUBIKEY' && (
          <div className="text-center py-6 space-y-5">
            <div className="relative w-20 h-20 mx-auto flex items-center justify-center">
              <div className="absolute inset-0 rounded-full bg-amber-400/30 animate-ping" />
              <div className="relative w-16 h-16 rounded-full bg-gradient-to-tr from-amber-500 to-yellow-400 text-slate-950 flex items-center justify-center shadow-xl shadow-amber-500/40">
                <Fingerprint className="w-9 h-9 animate-pulse text-slate-950" />
              </div>
            </div>
            <div>
              <h4 className="text-lg font-black text-slate-900">Insert & Touch Your YubiKey</h4>
              <p className="text-xs text-slate-600 font-bold max-w-xs mx-auto mt-1">
                Please insert your YubiKey hardware key into your USB port or tap via NFC, then touch the golden contact sensor.
              </p>
            </div>
            <button
              onClick={() => setStep('SHOW_OPTIONS')}
              className="text-xs font-black text-purple-700 hover:text-purple-900 underline transition-all"
            >
              Cancel & Back to Security Options
            </button>
          </div>
        )}

        {/* STEP 3B: TOTP Code Input */}
        {step === 'VERIFY_TOTP' && (
          <form onSubmit={handleVerifyTOTP} className="space-y-5">
            <div className="space-y-2 text-center">
              <label className="block text-xs font-black text-slate-800 uppercase tracking-widest">
                ENTER 6-DIGIT AUTHENTICATOR PASSCODE
              </label>
              <p className="text-xs text-slate-600 font-bold">
                Open your Authenticator app (Google Authenticator / Authy) and enter code.
              </p>
              <input
                type="text"
                maxLength={6}
                required
                autoFocus
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                placeholder="123456"
                className="w-full max-w-xs mx-auto px-4 py-4 rounded-2xl bg-indigo-50/50 border-2 border-indigo-300 text-center text-3xl font-mono tracking-widest text-indigo-900 placeholder-slate-300 font-black focus:outline-none focus:bg-white focus:border-indigo-600 focus:ring-4 focus:ring-indigo-600/10 transition-all shadow-inner"
              />
            </div>

            <div className="flex gap-3">
              <button
                type="button"
                onClick={() => setStep('SHOW_OPTIONS')}
                className="px-5 py-3.5 rounded-2xl bg-slate-100 hover:bg-slate-200 text-slate-700 font-black text-xs border border-slate-300 transition-all cursor-pointer"
              >
                Back
              </button>
              <button
                type="submit"
                disabled={loading}
                className="flex-1 py-3.5 rounded-2xl bg-gradient-to-r from-indigo-600 via-purple-600 to-cyan-500 hover:from-indigo-700 hover:to-cyan-600 text-white font-black text-sm shadow-xl shadow-indigo-600/30 transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
              >
                {loading ? 'Verifying Code...' : 'Verify TOTP Authenticator'}
              </button>
            </div>
          </form>
        )}

        {/* STEP 3C: Emergency Recovery Code Input */}
        {step === 'VERIFY_RECOVERY' && (
          <form onSubmit={handleVerifyRecoveryCode} className="space-y-5">
            <div className="space-y-2 text-center">
              <label className="block text-xs font-black text-slate-800 uppercase tracking-widest flex items-center justify-center gap-1.5">
                <Shield className="w-4 h-4 text-sky-600" />
                <span>ENTER EMERGENCY RECOVERY CODE</span>
              </label>
              <p className="text-xs text-slate-600 font-bold">
                Enter one of your 8 single-use break-glass codes (e.g. A8F92-K3L91).
              </p>
              <input
                type="text"
                required
                autoFocus
                value={recoveryCode}
                onChange={(e) => setRecoveryCode(e.target.value.toUpperCase())}
                placeholder="A8F92-K3L91"
                className="w-full max-w-xs mx-auto px-4 py-3.5 rounded-2xl bg-sky-50/50 border-2 border-sky-300 text-center text-xl font-mono tracking-wider text-sky-950 placeholder-slate-300 font-black focus:outline-none focus:bg-white focus:border-sky-600 focus:ring-4 focus:ring-sky-600/10 transition-all shadow-inner"
              />
            </div>

            <div className="flex gap-3">
              <button
                type="button"
                onClick={() => setStep('SHOW_OPTIONS')}
                className="px-5 py-3.5 rounded-2xl bg-slate-100 hover:bg-slate-200 text-slate-700 font-black text-xs border border-slate-300 transition-all cursor-pointer"
              >
                Back
              </button>
              <button
                type="submit"
                disabled={loading}
                className="flex-1 py-3.5 rounded-2xl bg-gradient-to-r from-sky-600 via-blue-600 to-indigo-600 hover:from-sky-700 hover:to-indigo-700 text-white font-black text-sm shadow-xl shadow-sky-600/30 transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
              >
                {loading ? 'Verifying Code...' : 'Verify Recovery Code'}
              </button>
            </div>
          </form>
        )}

        {/* STEP 4: Success Verified */}
        {step === 'VERIFIED' && (
          <div className="text-center space-y-5 py-4">
            <div className="relative w-20 h-20 mx-auto flex items-center justify-center">
              <div className="absolute inset-0 rounded-full bg-emerald-400/30 animate-pulse" />
              <div className="relative w-16 h-16 rounded-full bg-gradient-to-tr from-emerald-500 to-teal-400 text-white flex items-center justify-center shadow-xl shadow-emerald-500/40 text-2xl font-black">
                <Check className="w-9 h-9 stroke-[3]" />
              </div>
            </div>
            <div>
              <h4 className="text-xl font-black text-slate-900">Zero-Trust Session Verified!</h4>
              <p className="text-xs text-slate-600 font-bold max-w-sm mx-auto mt-1 leading-relaxed">
                Your identity has been authenticated & cryptographic session token issued via OSIVault Security Engine.
              </p>
            </div>
            <button
              onClick={onClose}
              className="w-full py-4 rounded-2xl bg-gradient-to-r from-emerald-600 to-teal-500 hover:from-emerald-700 hover:to-teal-600 text-white font-black text-sm shadow-xl shadow-emerald-600/30 transition-all cursor-pointer"
            >
              Continue to Platform →
            </button>
          </div>
        )}

        {/* Bottom Footer Action (Skip Option) */}
        {step !== 'VERIFIED' && (
          <div className="pt-4 border-t border-slate-100 flex items-center justify-between text-xs">
            <span className="text-slate-500 font-bold">Do not want extra MFA security right now?</span>
            <button
              onClick={onClose}
              className="px-4 py-2.5 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 font-extrabold border border-slate-200 hover:border-slate-300 transition-all cursor-pointer"
            >
              Skip & Continue to Platform →
            </button>
          </div>
        )}

      </div>
    </div>
  );
}
