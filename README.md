# Fullstack Development Course: Building Production-Ready Express APIs

## Overview

I taught fullstack development to 6 students selected from 50 applicants. The focus of the course was on building real production-ready Express APIs using TypeScript, Prisma, MongoDB, and Joi for validation.

## Project Description

The main project of this course is a Jira-like project management system. This comprehensive application allows admins to manage projects, tasks, teams, and contributors with a robust authentication and authorization system.

### Key Features

1. **Admin Management**:

    - Admins can create accounts with active or inactive statuses.
    - Admins manage their profiles, handle password resets, and oversee their associated tasks and projects.
    - Each admin can belong to a company and have specific roles.

2. **User Authentication and Authorization**:

    - The application has a solid authentication system to secure user accounts.
    - Authorization ensures that users have appropriate access levels based on their roles (e.g., admin, team member).

3. **Team Member Management**:

    - Admins can invite team members via email and assign them to specific projects.
    - Team members can have roles and statuses indicating their activity (active, inactive, deactivated).
    - Members can join projects, update their profiles, and manage their tasks.

4. **Project Management**:

    - Admins can create and manage projects with statuses such as active, on hold, archived, or completed.
    - Projects include detailed information such as name, description, progress, and timelines.
    - Admins can assign team members to projects and track their contributions.

5. **Task and Story Management**:

    - Admins and team members can create stories (major tasks or features) within projects.
    - Stories have statuses (to-do, in progress, blocked, done) and can be broken down into sub-tasks.
    - Tasks and sub-tasks help in managing work efficiently and tracking progress.

6. **Contributor Management**:
    - Contributors are team members assigned to specific projects.
    - Their statuses indicate their activity within the project, helping track who is working on what.
    - This allows for effective collaboration and task delegation within projects.

### Technologies Used

-   **TypeScript**: For type safety and enhanced code quality.
-   **Express**: To handle server-side logic and API endpoints.
-   **Prisma**: For managing database interactions with MongoDB.
-   **MongoDB**: As the primary database for storing application data.
-   **Joi**: For validating incoming data to maintain data integrity and security (implementation in progress).

### Conclusion

This project provides a comprehensive example of building scalable and maintainable backend services for a real-world project management system. It includes features for user management, project tracking, task management, and team collaboration, making it a robust solution for managing complex projects.

The biggest UI project we built is available at [Projectify App UI](https://github.com/aliramazon/projectify-app-ui), and the backend is available at [Projectify App API](https://github.com/aliramazon/projectify-app-api).
