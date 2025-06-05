const { PrismaClient } = require('../generated/prisma');
const prisma = new PrismaClient();
const bcrypt = require('bcryptjs');

async function main() {
  // Create or fetch Organizations
  const org1 = await prisma.organization.upsert({
    where: { name: 'Fredericton Community Kitchen' },
    update: {},
    create: {
      name: 'Fredericton Community Kitchen',
      address: '123 Main St, Fredericton',
    },
  });
  const org2 = await prisma.organization.upsert({
    where: { name: 'Saint John Food Bank' },
    update: {},
    create: {
      name: 'Saint John Food Bank',
      address: '456 King St, Saint John',
    },
  });

  // Create or fetch Shift Categories for org1
  const mealProgram = await prisma.shiftCategory.upsert({
    where: { name_organizationId: { name: 'Daily Meal Program', organizationId: org1.id } },
    update: {},
    create: { name: 'Daily Meal Program', icon: '🍽️', organizationId: org1.id },
  });
  const grabAndGo = await prisma.shiftCategory.upsert({
    where: { name_organizationId: { name: 'Grab & Go', organizationId: org1.id } },
    update: {},
    create: { name: 'Grab & Go', icon: '🧺', organizationId: org1.id },
  });
  const specialProject = await prisma.shiftCategory.upsert({
    where: { name_organizationId: { name: 'Special Project', organizationId: org1.id } },
    update: {},
    create: { name: 'Special Project', icon: '🌱', organizationId: org1.id },
  });
  const support = await prisma.shiftCategory.upsert({
    where: { name_organizationId: { name: 'Support', organizationId: org1.id } },
    update: {},
    create: { name: 'Support', icon: '🤝', organizationId: org1.id },
  });
  const collection = await prisma.shiftCategory.upsert({
    where: { name_organizationId: { name: 'Collection', organizationId: org1.id } },
    update: {},
    create: { name: 'Collection', icon: '📦', organizationId: org1.id },
  });

  // Create Donation Categories for org1
  const meat = await prisma.donationCategory.create({
    data: { name: 'Meat & Fish', icon: '🐟', organizationId: org1.id },
  });
  const grains = await prisma.donationCategory.create({
    data: { name: 'Bread Products', icon: '🍞', organizationId: org1.id },
  });
  const veg = await prisma.donationCategory.create({
    data: { name: 'Produce', icon: '🥕', organizationId: org1.id },
  });
  const dairy = await prisma.donationCategory.create({
    data: { name: 'Dairy', icon: '🧀', organizationId: org1.id },
  });
  const other = await prisma.donationCategory.create({
    data: { name: 'Other', icon: '…', organizationId: org1.id },
  });

  // Create Donors
  await prisma.donor.createMany({
    data: [
      { name: 'Walmart', location: 'Fredericton', contactInfo: 'walmart@example.com', kitchenId: org1.id },
      { name: 'Sobeys', location: 'Fredericton', contactInfo: 'sobeys@example.com', kitchenId: org1.id },
      { name: 'Costco', location: 'Saint John', contactInfo: 'costco@example.com', kitchenId: org2.id },
    ],
    skipDuplicates: true,
  });

  // Fetch org and category IDs
  const org1Id = org1.id;
  const org2Id = org2.id;
  const mealProgramCat = await prisma.shiftCategory.findFirst({ where: { name: 'Daily Meal Program', organizationId: org1Id } });
  const grabAndGoCat = await prisma.shiftCategory.findFirst({ where: { name: 'Grab & Go', organizationId: org1Id } });
  const specialProjectCat = await prisma.shiftCategory.findFirst({ where: { name: 'Special Project', organizationId: org1Id } });
  const supportCat = await prisma.shiftCategory.findFirst({ where: { name: 'Support', organizationId: org1Id } });

  // Seed shifts for org1
  await prisma.shift.createMany({
    data: [
      {
        name: 'Breakfast Shift',
        shiftCategoryId: mealProgramCat.id,
        startTime: new Date('2024-06-01T07:00:00'),
        endTime: new Date('2024-06-01T09:00:00'),
        location: 'Fredericton Community Kitchen',
        slots: 3,
        organizationId: org1Id,
      },
      {
        name: 'Lunch Shift',
        shiftCategoryId: mealProgramCat.id,
        startTime: new Date('2024-06-01T11:30:00'),
        endTime: new Date('2024-06-01T13:30:00'),
        location: 'Harvest House',
        slots: 1,
        organizationId: org1Id,
      },
      {
        name: 'Supper Shift',
        shiftCategoryId: mealProgramCat.id,
        startTime: new Date('2024-06-01T16:30:00'),
        endTime: new Date('2024-06-01T18:30:00'),
        location: 'Greener Village',
        slots: 5,
        organizationId: org1Id,
      },
      {
        name: 'Meal Pack Distribution',
        shiftCategoryId: grabAndGoCat.id,
        startTime: new Date('2024-06-01T14:00:00'),
        endTime: new Date('2024-06-01T16:00:00'),
        location: 'Fredericton Community Kitchen',
        slots: 2,
        organizationId: org1Id,
      },
      {
        name: 'Community Garden',
        shiftCategoryId: specialProjectCat.id,
        startTime: new Date('2024-06-01T10:00:00'),
        endTime: new Date('2024-06-01T12:00:00'),
        location: 'Greener Village',
        slots: 10,
        organizationId: org1Id,
      },
      {
        name: 'Support Shift',
        shiftCategoryId: supportCat.id,
        startTime: new Date('2024-06-01T09:00:00'),
        endTime: new Date('2024-06-01T17:00:00'),
        location: 'Harvest House',
        slots: 8,
        organizationId: org1Id,
      },
    ],
    skipDuplicates: true,
  });

  // Seed recurring shifts for org1 (e.g., every Monday, Wednesday, Friday)
  await prisma.recurringShift.createMany({
    data: [
      {
        name: 'Breakfast Shift',
        dayOfWeek: 1, // Monday
        startTime: new Date('1970-01-01T07:00:00'),
        endTime: new Date('1970-01-01T09:00:00'),
        shiftCategoryId: mealProgramCat.id,
        location: 'Fredericton Community Kitchen',
        slots: 3,
        organizationId: org1Id,
      },
      {
        name: 'Lunch Shift',
        dayOfWeek: 3, // Wednesday
        startTime: new Date('1970-01-01T11:30:00'),
        endTime: new Date('1970-01-01T13:30:00'),
        shiftCategoryId: mealProgramCat.id,
        location: 'Harvest House',
        slots: 2,
        organizationId: org1Id,
      },
      {
        name: 'Supper Shift',
        dayOfWeek: 5, // Friday
        startTime: new Date('1970-01-01T16:30:00'),
        endTime: new Date('1970-01-01T18:30:00'),
        shiftCategoryId: mealProgramCat.id,
        location: 'Greener Village',
        slots: 4,
        organizationId: org1Id,
      },
      // Grab & Go recurring shifts
      {
        name: 'Meal Pack Distribution',
        dayOfWeek: 2, // Tuesday
        startTime: new Date('1970-01-01T14:00:00'),
        endTime: new Date('1970-01-01T16:00:00'),
        shiftCategoryId: grabAndGoCat.id,
        location: 'Fredericton Community Kitchen',
        slots: 2,
        organizationId: org1Id,
      },
      // Special Project recurring shifts
      {
        name: 'Community Garden',
        dayOfWeek: 4, // Thursday
        startTime: new Date('1970-01-01T10:00:00'),
        endTime: new Date('1970-01-01T12:00:00'),
        shiftCategoryId: specialProjectCat.id,
        location: 'Greener Village',
        slots: 6,
        organizationId: org1Id,
      },
      // Support recurring shifts
      {
        name: 'Support Shift',
        dayOfWeek: 6, // Saturday
        startTime: new Date('1970-01-01T09:00:00'),
        endTime: new Date('1970-01-01T17:00:00'),
        shiftCategoryId: supportCat.id,
        location: 'Harvest House',
        slots: 5,
        organizationId: org1Id,
      },
      // Collection recurring shifts
      {
        name: 'Food Collection',
        dayOfWeek: 0, // Sunday
        startTime: new Date('1970-01-01T13:00:00'),
        endTime: new Date('1970-01-01T15:00:00'),
        shiftCategoryId: collection.id,
        location: 'Fredericton Community Kitchen',
        slots: 3,
        organizationId: org1Id,
      },
    ],
    skipDuplicates: true,
  });

  // Seed admin user for org1
  const existingAdmin = await prisma.user.findUnique({ where: { email: 'raj@gmail.com' } });
  if (!existingAdmin) {
    const hashedPassword = await bcrypt.hash('raj', 10);
    await prisma.user.create({
      data: {
        email: 'raj@gmail.com',
        password: hashedPassword,
        firstName: 'Raj',
        lastName: 'Admin',
        role: 'ADMIN',
        organizationId: org1.id,
      },
    });
    console.log('Seeded admin user: raj@gmail.com / raj');
  }

  console.log('Seed data created!');
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
