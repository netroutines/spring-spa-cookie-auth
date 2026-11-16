import { AppShell, Container } from '@mantine/core';
import { Outlet } from 'react-router';

export default function AppLayout() {
  return (
    <AppShell padding={{ base: 'md', sm: 'xl' }}>
      <AppShell.Main>
        <Container size="md">
          <Outlet />
        </Container>
      </AppShell.Main>
    </AppShell>
  );
}
