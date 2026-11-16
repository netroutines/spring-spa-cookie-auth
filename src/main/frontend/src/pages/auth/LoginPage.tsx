import { useEffect, useRef, useState } from 'react';
import { Alert, Anchor, Button, Card, PasswordInput, Stack, Text, TextInput, Title } from '@mantine/core';
import { useForm } from '@mantine/form';
import { Link, useLocation, useNavigate } from 'react-router';
import { AuthError, login } from '../../auth/api';
import { validateEmail, validatePassword } from '../../auth/validation';

export default function LoginPage() {
  const navigate = useNavigate();
  const state: unknown = useLocation().state;
  const registeredEmail = state !== null && typeof state === 'object'
    && 'registeredEmail' in state && typeof state.registeredEmail === 'string'
    ? state.registeredEmail : '';
  const [error, setError] = useState<string | null>(null);
  const request = useRef<AbortController | null>(null);
  const form = useForm({
    name: 'login',
    mode: 'uncontrolled',
    initialValues: { email: registeredEmail, password: '' },
    validate: { email: validateEmail, password: validatePassword },
  });

  useEffect(() => () => request.current?.abort(), []);

  async function handleSubmit(values: typeof form.values) {
    const controller = new AbortController();
    request.current = controller;
    setError(null);

    try {
      await login(values.email, values.password, controller.signal);
      if (!controller.signal.aborted) {
        form.setFieldValue('password', '');
        navigate('/app', { replace: true });
      }
    } catch (failure) {
      if (controller.signal.aborted) {
        return;
      }
      const status = failure instanceof AuthError ? failure.status : 0;
      setError(status === 401 ? 'Incorrect email or password.'
        : status === 403 ? 'Your request was rejected. Please try again to refresh the security token.'
        : status === 400 ? 'Please check your email and password and try again.'
        : 'Login is temporarily unavailable. Please try again.');
    } finally {
      request.current = null;
    }
  }

  return (
    <>
      <title>Login | Spring SPA Cookie Authentication</title>
      <Card withBorder radius="md" p={{ base: 'lg', sm: 'xl' }}>
        <Stack gap="lg">
          <Title order={1} size="h2">Login</Title>
          {registeredEmail && (
            <Alert color="green" role="status">
              Registration complete. Log in with your password.
            </Alert>
          )}
          {error && <Alert color="red" title="Unable to log in">{error}</Alert>}
          {/* Native email validation rejects some addresses accepted by Jakarta @Email. */}
          <form noValidate onSubmit={(event) => {
            if (request.current) {
              event.preventDefault();
              return;
            }
            form.onSubmit(handleSubmit, (errors) => {
              form.getInputNode(Object.keys(errors)[0])?.focus();
            })(event);
          }}>
            <Stack gap="md">
              <TextInput
                label="Email"
                name="email"
                type="email"
                autoComplete="username"
                autoCapitalize="none"
                spellCheck={false}
                size="md"
                required
                disabled={form.submitting}
                key={form.key('email')}
                {...form.getInputProps('email')}
              />
              <PasswordInput
                label="Password"
                name="password"
                autoComplete="current-password"
                visibilityToggleButtonProps={{ 'aria-label': 'Toggle password visibility' }}
                size="md"
                required
                disabled={form.submitting}
                key={form.key('password')}
                {...form.getInputProps('password')}
              />
              <Button type="submit" size="md" fullWidth loading={form.submitting}>Login</Button>
            </Stack>
          </form>
          <Text size="sm" ta="center">
            Need an account? <Anchor component={Link} to="/register">Register</Anchor>
          </Text>
        </Stack>
      </Card>
    </>
  );
}
