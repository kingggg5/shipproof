(() => {
  const menuToggle = document.querySelector('.menu-toggle');
  const siteNav = document.querySelector('#site-nav');

  if (menuToggle && siteNav) {
    menuToggle.addEventListener('click', () => {
      const isOpen = siteNav.classList.toggle('is-open');
      menuToggle.setAttribute('aria-expanded', String(isOpen));
    });

    siteNav.querySelectorAll('a').forEach((link) => {
      link.addEventListener('click', () => {
        siteNav.classList.remove('is-open');
        menuToggle.setAttribute('aria-expanded', 'false');
      });
    });
  }

  const tabs = [...document.querySelectorAll('.console-tab')];
  const panels = [...document.querySelectorAll('.console-output')];

  tabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      const output = tab.dataset.output;

      tabs.forEach((candidate) => {
        const selected = candidate === tab;
        candidate.classList.toggle('is-active', selected);
        candidate.setAttribute('aria-selected', String(selected));
      });

      panels.forEach((panel) => {
        const isVisible = panel.id === `sample-${output}`;
        panel.hidden = !isVisible;
        panel.classList.toggle('is-hidden', !isVisible);
      });
    });
  });

  const scanButton = document.querySelector('[data-scan-start]');
  const scanDemo = document.querySelector('.scan-demo');
  const scanState = document.querySelector('[data-scan-state]');
  const scanDuration = document.querySelector('[data-scan-duration]');
  const scanResult = document.querySelector('[data-scan-result]');
  const scanBadge = document.querySelector('[data-scan-badge]');
  const scanStages = [...document.querySelectorAll('[data-scan-stage]')];

  if (scanButton && scanDemo && scanState && scanDuration && scanResult && scanBadge && scanStages.length) {
    const isThai = document.documentElement.lang === 'th';
    const labels = isThai
      ? { running: 'กำลังรัน fixture ตัวอย่าง', done: 'หลักฐานพร้อมใช้งาน', doneResult: 'FAIL WITH FINDINGS', doneBadge: 'บล็อก 3 รายการ', runningStage: 'กำลังทำงาน', completeStage: 'เสร็จแล้ว', readyStage: 'พร้อม' }
      : { running: 'Running sample fixture', done: 'Evidence ready', doneResult: 'FAIL WITH FINDINGS', doneBadge: '3 blocking', runningStage: 'Running', completeStage: 'Done', readyStage: 'Ready' };
    let running = false;

    const wait = (duration) => new Promise((resolve) => window.setTimeout(resolve, duration));

    scanButton.addEventListener('click', async () => {
      if (running) return;
      running = true;
      scanButton.disabled = true;
      scanButton.innerHTML = `${labels.running} <span aria-hidden="true">…</span>`;
      scanDemo.classList.remove('is-complete');
      scanState.textContent = labels.running;
      scanResult.textContent = 'SCANNING…';
      scanBadge.textContent = 'evaluating';
      scanDuration.textContent = '00.00s';

      scanStages.forEach((stage) => {
        stage.classList.remove('is-running', 'is-complete');
        stage.querySelector('[data-stage-status]').textContent = labels.readyStage;
      });

      const timings = [380, 520, 440, 520];
      const clocks = ['00.38s', '00.90s', '01.34s', '01.86s'];
      for (let index = 0; index < scanStages.length; index += 1) {
        const stage = scanStages[index];
        stage.classList.add('is-running');
        stage.querySelector('[data-stage-status]').textContent = labels.runningStage;
        await wait(timings[index]);
        stage.classList.remove('is-running');
        stage.classList.add('is-complete');
        stage.querySelector('[data-stage-status]').textContent = labels.completeStage;
        scanDuration.textContent = clocks[index];
      }

      scanDemo.classList.add('is-complete');
      scanState.textContent = labels.done;
      scanResult.textContent = labels.doneResult;
      scanBadge.textContent = labels.doneBadge;
      scanButton.disabled = false;
      scanButton.innerHTML = `${isThai ? 'รันอีกครั้ง' : 'Run again'} <span aria-hidden="true">↻</span>`;
      running = false;
    });
  }
})();
