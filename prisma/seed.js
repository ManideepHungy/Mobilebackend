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
      incoming_dollar_value: 10.0,
      email: 'info@frederictoncommunitykitchen.com',
      mealsvalue: 10.0,
    },
  });
  const org2 = await prisma.organization.upsert({
    where: { name: 'Saint John Food Bank' },
    update: {},
    create: {
      name: 'Saint John Food Bank',
      address: '456 King St, Saint John',
      incoming_dollar_value: 8.0,
      email: 'info@saintjohnfoodbank.com',
      mealsvalue: 8.0,
    },
  });

  // Create Modules for Fredericton Community Kitchen (org1)
  const modulesOrg1 = await Promise.all([
    prisma.module.upsert({
      where: { name_organizationId: { name: 'Donation Management', organizationId: org1.id } },
      update: {},
      create: {
        name: 'Donation Management',
        description: 'Manage donations and food collection',
        organizationId: org1.id,
      },
    }),
    prisma.module.upsert({
      where: { name_organizationId: { name: 'Meal Counting', organizationId: org1.id } },
      update: {},
      create: {
        name: 'Meal Counting',
        description: 'Track and manage meal counts for shifts',
        organizationId: org1.id,
      },
    }),
    prisma.module.upsert({
      where: { name_organizationId: { name: 'Volunteer Meals Counting', organizationId: org1.id } },
      update: {},
      create: {
        name: 'Volunteer Meals Counting',
        description: 'Volunteers can count meals during their shifts',
        organizationId: org1.id,
      },
    }),
    prisma.module.upsert({
      where: { name_organizationId: { name: 'Volunteer Meal counting sub module', organizationId: org1.id } },
      update: {},
      create: {
        name: 'Volunteer Meal counting sub module',
        description: 'Sub-module for meal counting during shift checkout',
        organizationId: org1.id,
      },
    }),
    prisma.module.upsert({
      where: { name_organizationId: { name: 'Shift Management', organizationId: org1.id } },
      update: {},
      create: {
        name: 'Shift Management',
        description: 'Manage volunteer shifts and distribution',
        organizationId: org1.id,
      },
    }),
    prisma.module.upsert({
      where: { name_organizationId: { name: 'User Management', organizationId: org1.id } },
      update: {},
      create: {
        name: 'User Management',
        description: 'Manage group check-ins and user permissions',
        organizationId: org1.id,
      },
    }),
  ]);

  // Create Modules for Saint John Food Bank (org2)
  const modulesOrg2 = await Promise.all([
    prisma.module.upsert({
      where: { name_organizationId: { name: 'Donation Management', organizationId: org2.id } },
      update: {},
      create: {
        name: 'Donation Management',
        description: 'Manage donations and food collection',
        organizationId: org2.id,
      },
    }),
    prisma.module.upsert({
      where: { name_organizationId: { name: 'Meal Counting', organizationId: org2.id } },
      update: {},
      create: {
        name: 'Meal Counting',
        description: 'Track and manage meal counts for shifts',
        organizationId: org2.id,
      },
    }),
    prisma.module.upsert({
      where: { name_organizationId: { name: 'Volunteer Meals Counting', organizationId: org2.id } },
      update: {},
      create: {
        name: 'Volunteer Meals Counting',
        description: 'Volunteers can count meals during their shifts',
        organizationId: org2.id,
      },
    }),
    prisma.module.upsert({
      where: { name_organizationId: { name: 'Volunteer Meal counting sub module', organizationId: org2.id } },
      update: {},
      create: {
        name: 'Volunteer Meal counting sub module',
        description: 'Sub-module for meal counting during shift checkout',
        organizationId: org2.id,
      },
    }),
    prisma.module.upsert({
      where: { name_organizationId: { name: 'Shift Management', organizationId: org2.id } },
      update: {},
      create: {
        name: 'Shift Management',
        description: 'Manage volunteer shifts and distribution',
        organizationId: org2.id,
      },
    }),
    prisma.module.upsert({
      where: { name_organizationId: { name: 'User Management', organizationId: org2.id } },
      update: {},
      create: {
        name: 'User Management',
        description: 'Manage group check-ins and user permissions',
        organizationId: org2.id,
      },
    }),
  ]);

  // Combine all modules for easier reference
  const allModules = [...modulesOrg1, ...modulesOrg2];

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
  await prisma.donationCategory.createMany({
    data: [
      { name: 'Meat & Fish', icon: '🐟', organizationId: org1.id },
      { name: 'Bread Products', icon: '🍞', organizationId: org1.id },
      { name: 'Produce', icon: '🥕', organizationId: org1.id },
      { name: 'Dairy', icon: '🧀', organizationId: org1.id },
      { name: 'Other', icon: '…', organizationId: org1.id },
    ],
    skipDuplicates: true,
  });

  // Create Weighing Categories for org1
  await prisma.weighingCategory.createMany({
    data: [
      { category: 'Backpack', kilogram_kg_: 5.0, pound_lb_: 11.0, organizationId: org1.id },
      { category: 'Box', kilogram_kg_: 10.0, pound_lb_: 22.0, organizationId: org1.id },
      { category: 'Bag', kilogram_kg_: 2.0, pound_lb_: 4.4, organizationId: org1.id },
      { category: 'Tote', kilogram_kg_: 7.0, pound_lb_: 15.4, organizationId: org1.id },
      { category: 'Crate', kilogram_kg_: 12.0, pound_lb_: 26.4, organizationId: org1.id },
    ],
    skipDuplicates: true,
  });

  // Create Donation Locations (Primary locations like Walmart, Costco, Sobeys)
  await prisma.donationLocation.createMany({
    data: [
      { name: 'Walmart', location: 'Fredericton', contactInfo: 'walmart@example.com', kitchenId: org1.id },
      { name: 'Sobeys', location: 'Fredericton', contactInfo: 'sobeys@example.com', kitchenId: org1.id },
      { name: 'Costco', location: 'Saint John', contactInfo: 'costco@example.com', kitchenId: org2.id },
      { name: 'Superstore', location: 'Fredericton', contactInfo: 'superstore@example.com', kitchenId: org1.id },
      { name: 'No Frills', location: 'Saint John', contactInfo: 'nofrills@example.com', kitchenId: org2.id },
    ],
    skipDuplicates: true,
  });

  // Create Individual Donors (Optional individual donors)
  await prisma.donor.createMany({
    data: [
      { 
        firstName: 'John', 
        lastName: 'Smith', 
        email: 'john.smith@email.com', 
        phoneNumber: '506-555-0101',
        organizationName: 'Smith Family Foundation',
        donorType: 'Individual',
        kitchenId: org1.id 
      },
      { 
        firstName: 'Sarah', 
        lastName: 'Johnson', 
        email: 'sarah.johnson@email.com', 
        phoneNumber: '506-555-0102',
        organizationName: null,
        donorType: 'Individual',
        kitchenId: org1.id 
      },
      { 
        firstName: 'Mike', 
        lastName: 'Brown', 
        email: 'mike.brown@email.com', 
        phoneNumber: '506-555-0103',
        organizationName: 'Brown Enterprises',
        donorType: 'Organization',
        kitchenId: org2.id 
      },
      { 
        firstName: 'Lisa', 
        lastName: 'Davis', 
        email: 'lisa.davis@email.com', 
        phoneNumber: '506-555-0104',
        organizationName: null,
        donorType: 'Individual',
        kitchenId: org2.id 
      },
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
  let adminUser;
  if (!existingAdmin) {
    const hashedPassword = await bcrypt.hash('raj', 10);
          adminUser = await prisma.user.create({
        data: {
          email: 'raj@gmail.com',
          password: hashedPassword,
          firstName: 'Raj',
          lastName: 'Admin',
          role: 'ADMIN',
          status: 'APPROVED',
          organizationId: org1.id,
        },
      });
    console.log('Seeded admin user: raj@gmail.com / raj');
  } else {
    adminUser = existingAdmin;
  }

  // Seed volunteer users for org1
  const volunteerUsers = [
    {
      email: 'volunteer1@gmail.com',
      password: 'volunteer1',
      firstName: 'John',
      lastName: 'Volunteer',
      role: 'VOLUNTEER',
      organizationId: org1.id,
    },
    {
      email: 'volunteer2@gmail.com',
      password: 'volunteer2',
      firstName: 'Jane',
      lastName: 'Helper',
      role: 'VOLUNTEER',
      organizationId: org1.id,
    },
    {
      email: 'volunteer3@gmail.com',
      password: 'volunteer3',
      firstName: 'Mike',
      lastName: 'Support',
      role: 'VOLUNTEER',
      organizationId: org1.id,
    }
  ];

  const createdUsers = [];
  for (const userData of volunteerUsers) {
    const existingUser = await prisma.user.findUnique({ where: { email: userData.email } });
    if (!existingUser) {
      const hashedPassword = await bcrypt.hash(userData.password, 10);
      const user = await prisma.user.create({
        data: {
          email: userData.email,
          password: hashedPassword,
          firstName: userData.firstName,
          lastName: userData.lastName,
          role: userData.role,
          status: 'APPROVED',
          organizationId: userData.organizationId,
        },
      });
      createdUsers.push(user);
      console.log(`Seeded volunteer user: ${userData.email} / ${userData.password}`);
    } else {
      createdUsers.push(existingUser);
    }
  }

  // Create module permissions for admin user (full access to all modules for org1)
  for (const module of modulesOrg1) {
    await prisma.userModulePermission.upsert({
      where: {
        userId_organizationId_moduleId: {
          userId: adminUser.id,
          organizationId: org1.id,
          moduleId: module.id,
        },
      },
      update: { canAccess: true },
      create: {
        userId: adminUser.id,
        organizationId: org1.id,
        moduleId: module.id,
        canAccess: true,
      },
    });
  }

  // Create module permissions for volunteer users (limited access)
  for (const user of createdUsers) {
    // Volunteers get access to Donation Management, Meal Counting, Volunteer Meals Counting, Volunteer Meal counting sub module, and Shift Management
    const volunteerModules = modulesOrg1.filter(m => 
      m.name === 'Donation Management' || 
      m.name === 'Meal Counting' || 
      m.name === 'Volunteer Meals Counting' || 
      m.name === 'Volunteer Meal counting sub module' ||
      m.name === 'Shift Management'
    );
    
    for (const module of volunteerModules) {
      await prisma.userModulePermission.upsert({
        where: {
          userId_organizationId_moduleId: {
            userId: user.id,
            organizationId: org1.id,
            moduleId: module.id,
          },
        },
        update: { canAccess: true },
        create: {
          userId: user.id,
          organizationId: org1.id,
          moduleId: module.id,
          canAccess: true,
        },
      });
    }
  }

  // Create sample Terms & Conditions for organizations
  await prisma.termsAndConditions.createMany({
    data: [
      {
        organizationId: org1.id,
        version: '1.0',
        title: 'Volunteer Agreement - Fredericton Community Kitchen',
        fileUrl: 'https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf',
        fileName: 'volunteer_agreement_fredericton.pdf',
        fileSize: 245760, // 240KB
        isActive: true,
        createdBy: adminUser.id,
      },
      {
        organizationId: org1.id,
        version: '2.0',
        title: 'Code of Conduct - Fredericton Community Kitchen',
        fileUrl: 'https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf',
        fileName: 'code_of_conduct_fredericton.pdf',
        fileSize: 156800, // 153KB
        isActive: true,
        createdBy: adminUser.id,
      },
      {
        organizationId: org1.id,
        version: '1.0',
        title: 'Safety Guidelines - Fredericton Community Kitchen',
        fileUrl: 'https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf',
        fileName: 'safety_guidelines_fredericton.pdf',
        fileSize: 189440, // 185KB
        isActive: true,
        createdBy: adminUser.id,
      },
      {
        organizationId: org2.id,
        version: '1.0',
        title: 'Volunteer Agreement - Saint John Food Bank',
        fileUrl: 'https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf',
        fileName: 'volunteer_agreement_saintjohn.pdf',
        fileSize: 198400, // 194KB
        isActive: true,
        createdBy: adminUser.id,
      },
    ],
    skipDuplicates: true,
  });

  // Get all the created terms and conditions for org1
  const frederictonTerms = await prisma.termsAndConditions.findMany({
    where: { organizationId: org1.id, isActive: true }
  });

  // Create sample user agreements for volunteer users (for all active terms)
  if (frederictonTerms.length > 0) {
    for (const user of createdUsers) {
      for (const terms of frederictonTerms) {
        await prisma.userAgreement.upsert({
          where: {
            userId_organizationId_termsAndConditionsId: {
              userId: user.id,
              organizationId: org1.id,
              termsAndConditionsId: terms.id,
            },
          },
          update: {},
          create: {
            userId: user.id,
            organizationId: org1.id,
            termsAndConditionsId: terms.id,
            signature: `${user.firstName} ${user.lastName}`,
            signedDocumentUrl: `https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf`,
            ipAddress: '192.168.1.100',
            userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)',
          },
        });
      }
    }
  }

  console.log('Seed data created successfully!');
  console.log('Admin user: raj@gmail.com / raj');
  console.log('Volunteer users: volunteer1@gmail.com / volunteer1, volunteer2@gmail.com / volunteer2, volunteer3@gmail.com / volunteer3');
  console.log('Donation Locations: Walmart, Sobeys, Costco, Superstore, No Frills');
  console.log('Individual Donors: John Smith, Sarah Johnson, Mike Brown, Lisa Davis');
  console.log('Modules: Created organization-specific modules for both organizations');
  console.log('Terms & Conditions: Created for both organizations');
  console.log('User Agreements: Created for all volunteer users');
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
