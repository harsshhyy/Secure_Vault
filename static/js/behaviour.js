(function () {
    const trustScoreElement = document.getElementById('trustScore');
    const trustLabelElement = document.getElementById('trustLabel');
    const LOG_ENDPOINT = '/log_behavior';
    const CHECK_INTERVAL = 15000;

    const state = {
        keyEvents: [],
        mouseEvents: [],
        scrollEvents: [],
        clickCount: 0,
        navigationEvents: [],
        focusStart: Date.now(),
        pageStart: Date.now(),
        lastKeyDown: {},
        isLoggingOut: false,
    };

    function safeWindow() {
        return typeof window !== 'undefined' ? window : null;
    }

    function safeDocument() {
        return typeof document !== 'undefined' ? document : null;
    }

    function computeTypingMetrics() {
        const events = state.keyEvents;
        if (!events.length) {
            return { typingSpeed: 0, keyDelay: 0, holdTime: 0 };
        }
        let totalHold = 0;
        let totalFlight = 0;
        let count = 0;
        let lastTime = null;

        events.forEach((item) => {
            if (item.type === 'hold') {
                totalHold += item.duration;
                count += 1;
            }
            if (item.type === 'flight' && lastTime != null) {
                totalFlight += item.duration;
            }
            lastTime = item.timestamp;
        });

        const typingSpeed = events.length / Math.max((Date.now() - state.pageStart) / 1000, 1);
        const keyDelay = totalFlight > 0 && count > 0 ? totalFlight / count : 0;
        const holdTime = count > 0 ? totalHold / count : 0;

        return {
            typingSpeed: parseFloat(typingSpeed.toFixed(2)),
            keyDelay: parseFloat(keyDelay.toFixed(3)),
            holdTime: parseFloat(holdTime.toFixed(3)),
        };
    }

    function computeMouseMetrics() {
        const events = state.mouseEvents;
        if (!events.length) {
            return { mouseSpeed: 0, clickRate: 0 };
        }

        let totalDistance = 0;
        let totalTime = 0;
        let lastPos = null;
        let lastTime = null;

        events.forEach((evt) => {
            if (lastPos && lastTime != null) {
                const dx = evt.x - lastPos.x;
                const dy = evt.y - lastPos.y;
                const distance = Math.sqrt(dx * dx + dy * dy);
                totalDistance += distance;
                totalTime += Math.max(evt.timestamp - lastTime, 1);
            }
            lastPos = { x: evt.x, y: evt.y };
            lastTime = evt.timestamp;
        });

        const mouseSpeed = totalTime > 0 ? totalDistance / (totalTime / 1000) : 0;
        const clickRate = state.clickCount / Math.max((Date.now() - state.pageStart) / 60000, 1);

        return {
            mouseSpeed: parseFloat(mouseSpeed.toFixed(2)),
            clickRate: parseFloat(clickRate.toFixed(2)),
        };
    }

    function computeScrollMetrics() {
        const events = state.scrollEvents;
        if (!events.length) {
            return { scrollVelocity: 0, scrollCount: 0 };
        }

        let totalDistance = 0;
        let totalTime = 0;
        let lastScroll = null;

        events.forEach((evt) => {
            if (lastScroll) {
                totalDistance += Math.abs(evt.position - lastScroll.position);
                totalTime += Math.max(evt.timestamp - lastScroll.timestamp, 1);
            }
            lastScroll = evt;
        });

        const scrollVelocity = totalTime > 0 ? totalDistance / (totalTime / 1000) : 0;
        return {
            scrollVelocity: parseFloat(scrollVelocity.toFixed(2)),
            scrollCount: events.length,
        };
    }

    function computeTrustScore() {
        const typing = computeTypingMetrics();
        const mouse = computeMouseMetrics();
        const scroll = computeScrollMetrics();
        const sessionTime = Math.max((Date.now() - state.pageStart) / 1000, 1);

        let score = 100;
        score -= Math.min(Math.max((typing.typingSpeed - 8) * 4, 0), 25);
        score -= Math.min(Math.max((typing.keyDelay - 0.3) * 16, 0), 20);
        score -= Math.min(Math.max((mouse.mouseSpeed - 400) / 30, 0), 20);
        score -= Math.min(Math.max((mouse.clickRate - 2.5) * 10, 0), 15);
        score -= Math.min(Math.max((scroll.scrollVelocity - 500) / 50, 0), 10);
        score -= Math.min(Math.max((sessionTime - 600) / 60, 0), 10);
        score = Math.max(0, Math.min(100, Math.round(score)));

        return {
            score,
            status:
                score <= 20
                    ? '🔴 High Risk'
                    : score <= 50
                    ? '🟡 Medium Risk'
                    : '🟢 Normal',
            details: {
                typingSpeed: typing.typingSpeed,
                keyDelay: typing.keyDelay,
                mouseSpeed: mouse.mouseSpeed,
                clickRate: mouse.clickRate,
                scrollVelocity: scroll.scrollVelocity,
                sessionTime: parseInt(sessionTime, 10),
            },
        };
    }

    function updateTrustDisplay(score, label) {
        if (trustScoreElement) {
            trustScoreElement.textContent = `${score}`;
        }
        if (trustLabelElement) {
            trustLabelElement.textContent = label;
        }
    }

    function buildBehaviorPayload(action, details, featureVector) {
        return {
            action,
            details,
            trustScore: featureVector.score,
            featureVector: [
                featureVector.details.typingSpeed,
                featureVector.details.keyDelay,
                featureVector.details.mouseSpeed,
                featureVector.details.clickRate,
                featureVector.details.sessionTime,
            ],
        };
    }

    function sendBehaviorLog(action, details, featureVector) {
        if (state.isLoggingOut) return;

        const payload = buildBehaviorPayload(action, details, featureVector);
        fetch(LOG_ENDPOINT, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(payload),
            credentials: 'same-origin',
        })
            .then((response) => {
                if (!response.ok) {
                    return response.json().then((data) => {
                        if (data && data.status === 'logout') {
                            triggerLogout();
                        }
                    });
                }
                return response.json();
            })
            .catch(() => {
                // network error, keep tracking locally
            });
    }

    function triggerLogout() {
        if (state.isLoggingOut) return;
        state.isLoggingOut = true;
        const logoutUrl = '/logout';
        safeWindow()?.location?.assign(logoutUrl);
    }

    function recordNavigation() {
        const doc = safeDocument();
        if (!doc) return;
        state.navigationEvents.push({
            path: doc.location.pathname,
            timestamp: Date.now(),
        });
    }

    function handleKeystroke(event) {
        const now = Date.now();
        if (event.type === 'keydown') {
            state.lastKeyDown[event.code] = now;
        }
        if (event.type === 'keyup') {
            const downTime = state.lastKeyDown[event.code];
            if (downTime) {
                const duration = now - downTime;
                state.keyEvents.push({ type: 'hold', duration, timestamp: now });
                delete state.lastKeyDown[event.code];
            }
            const lastEvent = state.keyEvents.length ? state.keyEvents[state.keyEvents.length - 1] : null;
            if (lastEvent && lastEvent.type !== 'flight') {
                const flight = now - (lastEvent.timestamp || now);
                state.keyEvents.push({ type: 'flight', duration: flight, timestamp: now });
            }
        }
    }

    function handleMouseMove(event) {
        state.mouseEvents.push({ x: event.clientX, y: event.clientY, timestamp: Date.now() });
    }

    function handleScroll(event) {
        state.scrollEvents.push({ position: window.scrollY || window.pageYOffset, timestamp: Date.now() });
    }

    function handleClick(event) {
        state.clickCount += 1;
    }

    function handleVisibilityChange() {
        const status = document.visibilityState;
        state.navigationEvents.push({ event: 'visibility', status, timestamp: Date.now() });
    }

    function scheduleReport() {
        const metrics = computeTrustScore();
        updateTrustDisplay(metrics.score, metrics.status);

        if (metrics.score <= 20) {
            sendBehaviorLog('auto_logout', 'Trust score below threshold', metrics);
            triggerLogout();
            return;
        }

        sendBehaviorLog('heartbeat', 'Periodic behavior heartbeat', metrics);
        setTimeout(scheduleReport, CHECK_INTERVAL);
    }

    function attachListeners() {
        const win = safeWindow();
        const doc = safeDocument();
        if (!win || !doc) return;

        recordNavigation();
        scheduleReport();

        win.addEventListener('keydown', handleKeystroke, true);
        win.addEventListener('keyup', handleKeystroke, true);
        win.addEventListener('mousemove', handleMouseMove, true);
        win.addEventListener('click', handleClick, true);
        win.addEventListener('scroll', handleScroll, true);
        doc.addEventListener('visibilitychange', handleVisibilityChange, true);
        win.addEventListener('popstate', recordNavigation, true);
        win.addEventListener('beforeunload', function () {
            const metrics = computeTrustScore();
            navigator.sendBeacon(
                LOG_ENDPOINT,
                JSON.stringify(buildBehaviorPayload('navigation_end', 'User leaving page', metrics))
            );
        });
    }

    function triggerTestAnomaly() {
        const badVector = [20, 2.0, 2000, 15, 2000]; // Extreme values to force low trust score
        sendBehaviorLog('test_anomaly', 'Manual anomaly test triggered', { score: 0, status: '🔴 High Risk', details: { typingSpeed: 20, keyDelay: 2.0, mouseSpeed: 2000, clickRate: 15, sessionTime: 2000 } });
    }

    // Attach to button if it exists
    const testBtn = document.getElementById('testAnomalyBtn');
    if (testBtn) {
        testBtn.addEventListener('click', triggerTestAnomaly);
    }

    attachListeners();
})();