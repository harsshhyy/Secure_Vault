// decoy.js — send interactions to /decoy_event for logging
(function(){
    function decoyAction(action, filename){
        const payload = { action: action, details: filename };
        navigator.sendBeacon && (function(){
            try{
                const url = '/decoy_event';
                const blob = new Blob([JSON.stringify(payload)], {type: 'application/json'});
                navigator.sendBeacon(url, blob);
            }catch(e){
                fetch('/decoy_event', {method:'POST', credentials:'same-origin', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)}).catch(()=>{});
            }
        })();
        // Provide plausible UI feedback
        if(action === 'download'){
            alert('Preparing download...');
        } else if(action === 'preview'){
            alert('Opening preview...');
        } else if(action === 'delete'){
            alert('File marked for deletion.');
        }
    }

    window.decoyAction = decoyAction;
    // send a heartbeat
    setInterval(function(){
        try{
            navigator.sendBeacon('/decoy_event', new Blob([JSON.stringify({action:'heartbeat', details: 'decoy_heartbeat'})], {type:'application/json'}));
        }catch(e){
            fetch('/decoy_event', {method:'POST', credentials:'same-origin', headers:{'Content-Type':'application/json'}, body: JSON.stringify({action:'heartbeat', details:'decoy_heartbeat'})}).catch(()=>{});
        }
    }, 15000);
})();
