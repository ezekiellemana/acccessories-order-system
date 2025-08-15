import React, { useEffect, useState, useRef, useCallback } from 'react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import useAuthStore from '../store/useAuthStore';

export default function IdleWarningModal({
  onStayLoggedIn,
  onForceLogout,
  warningDurationSec = 60,
  idleThresholdSec = 180, // 3 minutes
}) {
  // Hooks must be at the top
  const user = useAuthStore((s) => s.user);
  const skip = useAuthStore((s) => s.skipIdleWarning);
  const setSkip = useAuthStore((s) => s.setSkipIdleWarning);

  const [warningOpen, setWarningOpen] = useState(false);
  const [secondsLeft, setSecondsLeft] = useState(warningDurationSec);
  const countdownRef = useRef(null);
  const idleTimerRef = useRef(null);

  const resetIdleTimer = useCallback(() => {
    clearTimeout(idleTimerRef.current);
    if (warningOpen) return;
    idleTimerRef.current = setTimeout(() => {
      setWarningOpen(true);
    }, idleThresholdSec * 1000);
  }, [idleThresholdSec, warningOpen]);

  // Set up idle detection
  useEffect(() => {
    if (!user || skip) return;
    const events = ['mousemove', 'keydown', 'click', 'touchstart'];
    events.forEach((e) => window.addEventListener(e, resetIdleTimer));
    resetIdleTimer();
    return () => {
      clearTimeout(idleTimerRef.current);
      events.forEach((e) => window.removeEventListener(e, resetIdleTimer));
    };
  }, [user, skip, resetIdleTimer]);

  // Countdown when modal opens
  useEffect(() => {
    if (!warningOpen) return;
    setSecondsLeft(warningDurationSec);
    clearInterval(countdownRef.current);
    countdownRef.current = setInterval(() => {
      setSecondsLeft((prev) => {
        if (prev <= 1) {
          clearInterval(countdownRef.current);
          onForceLogout();
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(countdownRef.current);
  }, [warningOpen, warningDurationSec, onForceLogout]);

  const handleStay = useCallback(() => {
    clearInterval(countdownRef.current);
    setWarningOpen(false);
    resetIdleTimer();
    onStayLoggedIn();
  }, [onStayLoggedIn, resetIdleTimer]);

  // Only render for authenticated users who haven't skipped warning
  if (!user || skip) return null;

  const progressPct = (secondsLeft / warningDurationSec) * 100;

  return (
    <Dialog open={warningOpen} onOpenChange={(open) => !open && handleStay()}>
      <DialogContent className="max-w-sm">
        <DialogHeader>
          <DialogTitle className="text-lg">Heads up! You’re about to be logged out</DialogTitle>
          <DialogDescription className="mt-2">
            You’ve been idle for a bit. You’ll be logged out in{' '}
            <strong className="font-mono">{secondsLeft}s</strong>
          </DialogDescription>
        </DialogHeader>

        <div className="w-full h-2 bg-neutral-200 rounded-full overflow-hidden my-4">
          <div
            className="h-full bg-primary-500 transition-all"
            style={{ width: `${progressPct}%` }}
          />
        </div>

        <div className="flex items-center mb-6">
          <input
            id="skip-warning"
            type="checkbox"
            checked={skip}
            onChange={(e) => setSkip(e.target.checked)}
            className="mr-2"
          />
          <label htmlFor="skip-warning" className="text-sm">
            Don’t show again
          </label>
        </div>

        <DialogFooter className="flex justify-end space-x-2">
          <Button variant="outline" onClick={onForceLogout}>
            Logout Now
          </Button>
          <Button onClick={handleStay}>Stay Logged In</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
