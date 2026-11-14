import { Button, Container, Stack, Text, Title } from '@mantine/core';

export default function App() {
  return (
    <Container size="sm" py="xl">
      <Stack gap="md">
        <Title order={1}>My Agenda</Title>

        <Text c="dimmed">
          Spring Boot + React + Vite + Mantine
        </Text>

        <Button>
          Hello, World!
        </Button>
      </Stack>
    </Container>
  );
}
