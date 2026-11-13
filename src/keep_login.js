// DMM 로그인 페이지의 "ログインしたままにする"(로그인 상태 유지)를 미리 체크해 둠.
// 아이디·비밀번호 입력이나 로그인 제출은 하지 않음. 사용자가 직접 해제하면 다시 건드리지 않음.
(() => {
  if (location.hostname !== 'accounts.dmm.com') return;
  let userTouched = false;
  let attempts = 0;

  const ensureChecked = () => {
    if (userTouched || attempts >= 5) return true;
    const cb = document.getElementById('use_auto_login');
    if (!cb) return false;
    if (!cb.checked) {
      attempts += 1;
      cb.click(); // 화면 프레임워크의 상태도 함께 바뀌도록 클릭으로 처리
    }
    return true;
  };

  const markUser = (e) => {
    if (!e.isTrusted) return;
    const t = e.target;
    if (t && (t.id === 'use_auto_login' || (t.closest && t.closest('label[for="use_auto_login"]')))) userTouched = true;
  };
  document.addEventListener('pointerdown', markUser, true);
  document.addEventListener('keydown', markUser, true);

  const start = () => {
    const mo = new MutationObserver(() => ensureChecked());
    mo.observe(document.documentElement, { childList: true, subtree: true });
    ensureChecked();
    // 페이지 스크립트가 늦게 초기화되며 체크를 되돌리는 경우에 대비해 잠시 다시 확인
    [500, 1500, 3000].forEach((ms) => setTimeout(ensureChecked, ms));
    setTimeout(() => mo.disconnect(), 15000);
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
})();
