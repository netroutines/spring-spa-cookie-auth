import { useEffect, useRef, useState } from 'react';
import { Alert, Button, Center, Loader, Stack, Text, Title, VisuallyHidden } from '@mantine/core';
import { useNavigate } from 'react-router';
import { AuthError, currentUser, logout } from '../auth/api';
import type { UserResponse } from '../auth/api';

export default function DashboardPage() {
  const navigate = useNavigate();
  const [user, setUser] = useState<UserResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [loggingOut, setLoggingOut] = useState(false);
  const [logoutError, setLogoutError] = useState<string | null>(null);
  const logoutRequest = useRef<AbortController | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    async function loadUser() {
      try {
        const response = await currentUser(controller.signal);
        if (controller.signal.aborted) {
          return;
        }
        if (response === null) {
          navigate('/login', { replace: true });
        } else {
          setUser(response);
          setLoading(false);
        }
      } catch (failure) {
        if (!controller.signal.aborted) {
          setLoadError(failure instanceof AuthError && failure.status === 403
            ? 'Access to your dashboard was denied. Please try again.'
            : 'We could not check your session. Please try again.');
          setLoading(false);
        }
      }
    }
    void loadUser();
    return () => controller.abort();
  }, [navigate, attempt]);

  useEffect(() => () => logoutRequest.current?.abort(), []);

  async function handleLogout() {
    if (logoutRequest.current) {
      return;
    }
    const controller = new AbortController();
    logoutRequest.current = controller;
    setLoggingOut(true);
    setLogoutError(null);
    try {
      await logout(controller.signal);
      if (!controller.signal.aborted) {
        setUser(null);
        navigate('/login', { replace: true });
      }
    } catch (failure) {
      if (!controller.signal.aborted) {
        setLogoutError(failure instanceof AuthError && failure.status === 403
          ? 'Logout was rejected. Please try again to refresh the security token.'
          : 'Logout could not be confirmed. Please try again.');
      }
    } finally {
      logoutRequest.current = null;
      if (!controller.signal.aborted) {
        setLoggingOut(false);
      }
    }
  }

  return (
    <>
      <title>Dashboard | My Agenda</title>
      <Stack gap="lg" py="xl" align="flex-start">
        <Title order={1}>Dashboard</Title>
        {loading && (
          <Center role="status" py="md">
            <Loader size="sm" aria-hidden="true" />
            <VisuallyHidden>Checking your session…</VisuallyHidden>
          </Center>
        )}
        {loadError && (
          <>
            <Alert color="red" title="Dashboard unavailable">{loadError}</Alert>
            <Button variant="default" onClick={() => {
              setLoadError(null);
              setLoading(true);
              setAttempt((value) => value + 1);
            }}>Try again</Button>
          </>
        )}
        {user && (
          <>
            <Text size="lg" style={{ overflowWrap: 'anywhere', maxWidth: '100%' }}>Hello, {user.name}</Text>
            {logoutError && <Alert color="red" title="Unable to log out">{logoutError}</Alert>}
            <Button onClick={handleLogout} loading={loggingOut}>Logout</Button>
          </>
        )}
      </Stack>
    </>
  );
}
