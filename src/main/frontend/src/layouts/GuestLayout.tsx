import { Box, Center } from '@mantine/core';
import { Outlet } from 'react-router';

export default function GuestLayout() {
  return (
    <Center component="main" mih="100dvh" px="md" py="xl">
      <Box w="100%" maw={440}>
        <Outlet />
      </Box>
    </Center>
  );
}
