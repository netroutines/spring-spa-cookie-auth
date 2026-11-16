import { useEffect, useRef, useState } from 'react';
import { Alert, Anchor, Button, Card, PasswordInput, Stack, Text, TextInput, Title } from '@mantine/core';
import { useForm } from '@mantine/form';
import { Link, useNavigate } from 'react-router';
import { AuthError, register } from '../../auth/api';
import { validateEmail, validateName, validatePassword } from '../../auth/validation';

export default function RegisterPage() {
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);
  const request = useRef<AbortController | null>(null);
  const form = useForm({
    name: 'register',
    mode: 'uncontrolled',
    initialValues: { name: '', email: '', password: '' },
    validate: { name: validateName, email: validateEmail, password: validatePassword },
  });

  useEffect(() => () => request.current?.abort(), []);

  async function handleSubmit(values: typeof form.values) {
    const controller = new AbortController();
    request.current = controller;
    setError(null);

    try {
      const response = await register(values, controller.signal);
      if (!controller.signal.aborted) {
        form.setFieldValue('password', '');
        navigate('/login', { replace: true, state: { registeredEmail: response.email } });
      }
    } catch (failure) {
      if (controller.signal.aborted) {
        return;
      }
      const status = failure instanceof AuthError ? failure.status : 0;
      if (status === 409) {
        form.setFieldError('email', 'This email is already registered. Log in or use another email.');
      }
      setError(status === 409 ? 'An account with this email already exists.'
        : status === 400 ? 'The details were not accepted. Check your name, email and password.'
        : status === 403 ? 'Your request was rejected. Please try again to refresh the security token.'
        : 'Registration is temporarily unavailable. Please try again.');
    } finally {
      request.current = null;
    }
  }

  return (
    <>
      <title>Register | My Agenda</title>
      <Card withBorder radius="md" p={{ base: 'lg', sm: 'xl' }}>
        <Stack gap="lg">
          <Title order={1} size="h2">Register</Title>
          {error && <Alert color="red" title="Unable to register">{error}</Alert>}
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
                label="Name (optional)"
                description="If left blank, a name is created from your email."
                name="name"
                autoComplete="name"
                size="md"
                disabled={form.submitting}
                key={form.key('name')}
                {...form.getInputProps('name')}
              />
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
                description="Use 8–1024 characters. Spaces and Unicode are allowed."
                name="password"
                autoComplete="new-password"
                visibilityToggleButtonProps={{ 'aria-label': 'Toggle password visibility' }}
                size="md"
                required
                disabled={form.submitting}
                key={form.key('password')}
                {...form.getInputProps('password')}
              />
              <Button type="submit" size="md" fullWidth loading={form.submitting}>Register</Button>
            </Stack>
          </form>
          <Text size="sm" ta="center">
            Already have an account? <Anchor component={Link} to="/login">Login</Anchor>
          </Text>
        </Stack>
      </Card>
    </>
  );
}
